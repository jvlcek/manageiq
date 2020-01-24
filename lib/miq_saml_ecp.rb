require 'json'
require 'net/http'
require 'openssl'
require 'uri'
require 'nokogiri'
require 'pp'

class MiqSamlEcpError < StandardError; end
class MiqSamlEcpAuthError < StandardError; end

class MiqSamlEcp
  include Vmdb::Logging

  NS_ECP                  = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze
  NS_PAOS                 = "urn:liberty:paos:2003-08".freeze
  NS_SOAP                 = "http://schemas.xmlsoap.org/soap/envelope/".freeze
  NS_SAMLP                = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
  NS_SAML                 = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
  NAMESPACES              = { "ecp": NS_ECP, "paos": NS_PAOS, "soap": NS_SOAP, "samlp": NS_SAMLP, "saml": NS_SAML }.freeze

  SOAP_ACTOR              = "http://schemas.xmlsoap.org/soap/actor/next".freeze
  SOAP_MUST_UNDERSTAND    = "1".freeze

  SAML_METADATA_FILE      = "/etc/httpd/saml2/idp-metadata.xml".freeze
  SAML_CONF_FILE          = "/etc/httpd/conf.d/manageiq-external-auth-saml.conf".freeze

  attr_reader :user, :password,
    :sp_response_consumer_url, :sp_message_id, :sp_relay_state,
    :idp_response_xml, :idp_assertion_consumer_url, :idp_saml_response_xml

  def initialize(user, password)
    @user = user
    @password = password

    # IdP Response
    @idp_response_xml = nil
    @idp_assertion_consumer_url = nil
    @idp_saml_response_xml = nil

  end

  def authenticate
    begin
      paos_request_text = issues_request_to_sp
      paos_request_xml = process_paos_request(paos_request_text)

      authn_request = build_authn_request(paos_request_xml)
      send_authn_request_to_idp(authn_request)

      check_for_auth_errors
      process_idp_response

      sp_response_xml = build_sp_error_response || build_sp_response
      send_sp_response(sp_response_xml)

      get_user_attrs(sp_response_xml)
    rescue MiqSamlEcpError, MiqSamlEcpAuthError => err
      _log.warn("#{err.class}: #{err.message}")
      return {}
    end

  end

  #
  # This is the first step in the ECP process.
  #
  # A request has been made for a resource from the MiQ SP server but must be
  # authenticate first. 
  #
  # The ECP client, as implemented by this class,  indicates it's intent to
  # participate in the ECP flow by sending two special HTTP headers (Accept & PAOS)
  # to the MiQ SP which must me correctly configured for HTTP based SAML.
  #
  # The SAML configured MiQ SP will then respond by returning a PAOS request.
  # and then forward it to the IdP.
  #
  # This function sends the request to the MiQ SP along with the special
  # headers and stores the received PAOS request.
  #
  def issues_request_to_sp
    sp_resource = determine_sp_resource
    _log.debug("Using sp resource : #{sp_resource}")

    sp_resource_uri = URI.parse(sp_resource)
    sp_resource_http = Net::HTTP.new(sp_resource_uri.host, sp_resource_uri.port)
    sp_resource_http.use_ssl = true
    sp_resource_http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Get.new(sp_resource_uri.request_uri)
    request["Accept"] = "text/html, application/vnd.paos+xml"
    request["PAOS"]   = 'ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'

    sp_resource_http.request(request).body
  end

  
  # 
  # The received PAOS request is parsed and an XML object is build
  # to operate on.
  # 
  # The primary purpose of this step is to extract the
  # authnRequest from the PAOS request and encapsulate it in a new
  # SOAP request that can be forwarded to the IdP.
  #
  # The PAOS request also contains additional information some of
  # which must be preserved for the later step when we forward the
  # IdP response back.
  #
  # 1. The paos:Request responseConsumerURL is preserved because
  #    the ECP client MUST assure it matches the
  #    ecp:Response.AssertionConsumerServiceURL returned by the
  #    IdP to prevent man-in-the-middle attacks. It must also
  #    match the samlp:AuthnRequest.AssertionConsumerServiceURL.
  # 
  # 2. If the paos:Request contains a messageID it is preserved
  #    to be returned in the subsequent paos:Response.refToMessageID,
  #    allowing a provider to correlate messages.
  # 
  # 3. If a ecp:RelayState is present it is preserved because when
  #    the ECP client sends the response to the SP it MUST include
  #    RelayState provided in the request.
  # 
  def process_paos_request(paos_request_text)
    paos_request_xml = Nokogiri.XML(paos_request_text)

    @sp_response_consumer_url = get_xml_element_text(paos_request_xml, true,  '/soap:Envelope/soap:Header/paos:Request/@responseConsumerURL')
    @sp_message_id            = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/paos:Request/@messageID')
    @sp_relay_state           = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/ecp:RelayState')

    log_paos_request(paos_request_xml)

    paos_request_xml
  end

  def build_authn_request(paos_request_xml)
    idp_request_xml = paos_request_xml.dup
    idp_request_xml.xpath('/soap:Envelope/soap:Header', NAMESPACES).each(&:remove)
    idp_request_xml.inner_html.encode('utf-8')
  end

  def send_authn_request_to_idp(idp_request_text)
    idp_endpoint = determine_idp_endpoint
    idp_endpoint_uri = URI.parse(idp_endpoint)
    idp_endpoint_http = Net::HTTP.new(idp_endpoint_uri.host, idp_endpoint_uri.port)

    request = Net::HTTP::Post.new(idp_endpoint)
    request["Content-Type"] = "text/xml"
    request.basic_auth(@user, @password)
    request.body = idp_request_text

    idp_response_text = idp_endpoint_http.request(request).body
    _log.debug("SOAP message from ECP to IdP:\n #{idp_response_text}")

    @idp_response_xml = Nokogiri.XML(idp_response_text)
  end

  def process_idp_response
    @idp_saml_response_xml =      get_xml_element(@idp_response_xml, true, '/soap:Envelope/soap:Body/samlp:Response')
    @idp_assertion_consumer_url = get_xml_element_text(ecp_response_from_soap_attrs, true, './@AssertionConsumerServiceURL')

    log_idp_response_info
  end

  def build_sp_response
    nsmap = @idp_response_xml.namespaces
    nsmap['xmlns:paos'] = NS_PAOS
    nsmap['xmlns:ecp'] = NS_ECP
    soap_ns = nsmap.detect { |n,v| v == NS_SOAP}.first.gsub("xmlns:","")

    builder = Nokogiri::XML::Builder.new do |xml|
      xml[soap_ns].Envelope(nsmap) do |envelope|

        if @sp_message_id || @sp_relay_state
          envelope[soap_ns].Header(nsmap) do |header|
            if @sp_message_id
              header["paos"].Response("#{soap_ns}:actor" => SOAP_ACTOR,
                                      "#{soap_ns}:mustUnderstand" => SOAP_MUST_UNDERSTAND,
                                      "paos:refToMessageID" => @sp_message_id)
            end
            if @sp_relay_state
              header["ecp"].RelayState(@sp_relay_state,
                                       "#{soap_ns}:actor" => SOAP_ACTOR,
                                       "#{soap_ns}:mustUnderstand" => SOAP_MUST_UNDERSTAND)
             # JJV MISSING LINE 896 https://github.com/jdennis/saml_ecp_demo/blob/master/saml_ecp_demo/saml_ecp_demo.py#L896
             # JJV ecp_relay_state.text = self.sp_relay_state
            end
          end
        end # envelope
        envelope[soap_ns].Body
      end # xml
    end # builder

    @idp_saml_response_xml.children.last.default_namespace = @idp_saml_response_xml.children.last.namespaces["xmlns:saml"]
    builder.doc.xpath("//#{soap_ns}:Body").first  << @idp_saml_response_xml

    builder.doc
  end

  def build_sp_error_response
    if (@sp_response_consumer_url != @idp_assertion_consumer_url)
      err_msg = "responseConsumerURL=#{@sp_response_consumer_url} does not match AssertionConsumerServiceURL=#{@idp_assertion_consumer_url}"
      build_soap_fault('server', 'invalid response', err_msg)
    end
  end

  def send_sp_response(sp_response_xml)
    sp_response_consumer_url_uri = URI.parse(@sp_response_consumer_url)
    sp_response_consumer_url_http = Net::HTTP.new(sp_response_consumer_url_uri.host, sp_response_consumer_url_uri.port)
    sp_response_consumer_url_http.use_ssl = true
    sp_response_consumer_url_http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Post.new(sp_response_consumer_url_uri.request_uri)
    request["Content-Type"] = "application/vnd.paos+xml"
    sp_response_text = sp_response_xml.inner_html.encode('utf-8')

    # correct the saml namespace
    sp_response_text.gsub!('Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"', 'saml:Assertion')
    sp_response_text.gsub!('Assertion>', 'saml:Assertion>')
    sp_response_text.gsub!('Issuer>', 'saml:Issuer>')
    sp_response_text.gsub!('Subject>', 'saml:Subject>')
    sp_response_text.gsub!('saml:saml', 'saml')

    request.body = sp_response_text

    response = sp_response_consumer_url_http.request(request)
    _log.debug("--- SP Resource ---\n#{response.body}")
  end

  def get_user_attrs(sp_response_xml)
    user_attrs = sp_response_xml.xpath("//saml:Attribute").each_with_object({}) { |n,h| h[n["Name"]] = n.text }
    user_attrs["groups"] = sp_response_xml.xpath("//saml:Attribute[@Name='groups']").map(&:text)
    user_attrs.delete("domain") unless collecting_domain?

    log_user_attrs(user_attrs)

    user_attrs
  end

  private

  def build_soap_fault(fault_code, fault_string, detail=nil)
    builder = Nokogiri::XML::Builder.new { |xml|
      xml['soap'].Envelope("xmlns:soap" => NS_SOAP) { |envelope|
        envelope['soap'].Body { |body|
          body['soap'].Fault { |fault|
            fault.faultcode("soap:#{fault_code}")
            fault.faultstring(fault_string)
            fault.detail(detail) unless detail.nil?
          }
        }
      }
    }

    builder_xml = builder.to_xml.gsub!("soap:faultcode", "faultcode").gsub!("soap:faultstring", "faultstring").gsub!("soap:detail", "detail")

    return Nokogiri::XML(builder_xml)
  end

  def collecting_domain?
    File.open(SAML_CONF_FILE) do |file|
      file.grep(/REMOTE_USER_DOMAIN/)
    end.count != 0
  end

  def determine_idp_endpoint
    File.open(SAML_METADATA_FILE) { |file| file.grep(/Location/) }.map(&:strip).uniq.first.split('"')[1]
  end

  def determine_sp_resource
    "https://#{LinuxAdmin::Hosts.new.hostname}/saml_login"
  end

  def ecp_response_from_soap_attrs
    ecp_response = get_xml_element(@idp_response_xml, true, '/soap:Envelope/soap:Header/ecp:Response')
    description = "IdP to ECP messge, ecp:Response"

    soap_actor = get_xml_element_text(ecp_response, false, './@soap:actor')
    raise MiqSamlEcpError, "#{description} is missing required soap:actor attribute" if soap_actor.nil?
    raise MiqSamlEcpError, "#{description} %s has invalid soap:actor value: #{soap_actor}, expecting #{SOAP_ACTOR}" if soap_actor != SOAP_ACTOR

    soap_must_understand = get_xml_element_text(ecp_response, false, './@soap:mustUnderstand')
    raise MiqSamlEcpError, "#{description} is missing required soap:mustUnderstand attribute" if soap_must_understand.nil?
    raise MiqSamlEcpError, "#{description} has invalid soap:actor value: #{soap_must_understand}, expecting #{SOAP_MUST_UNDERSTAND}" if soap_must_understand != SOAP_MUST_UNDERSTAND

    ecp_response
  end

  def get_xml_element(context_node, required, xpath_expr)
    matches = context_node.xpath(xpath_expr, NAMESPACES)

    if matches.count == 0
      raise MiqSamlEcpError, "#{xpath_expr} not found " if required
      return nil
    end

    raise MiqSamlEcpError, "found #{matches.count} multiple matches for #{xpath_expr}" if matches.count > 1

    return matches.first
  end

  def get_xml_element_text(context_node, required, xpath_expr)
    data = get_xml_element(context_node, required, xpath_expr)

    return data.children.first.text if data.respond_to?("children")

    return data.nil? ? nil : data.value
  end

  def check_for_auth_errors
    kc_error = @idp_response_xml.xpath("//namespace:div[@id='kc-error-message']/namespace:p[@class]", "namespace" => "http://www.w3.org/1999/xhtml")
    raise MiqSamlEcpAuthError, kc_error.text unless kc_error.empty?
  end

  def log_idp_response_info
    idp_request_authenticated       = get_xml_element(@idp_response_xml, false, '/soap:Envelope/soap:Header/ecp:RequestAuthenticated')
    idp_saml_response_status_code   = get_xml_element_text(@idp_saml_response_xml, true, './samlp:Status/samlp:StatusCode/@Value')
    idp_saml_response_status_code2  = get_xml_element_text(@idp_saml_response_xml, false, './samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value')
    idp_saml_response_status_msg    = get_xml_element_text(@idp_saml_response_xml, false, './samlp:Status/samlp:StatusMessage')
    idp_saml_response_status_detail = get_xml_element_text(@idp_saml_response_xml, false, './samlp:Status/samlp:StatusDetail')

    _log.debug("\n=== Log IdP SOAP Response Info ===")
    _log.debug("SAML Status Code:           #{idp_saml_response_status_code || 'None'}")
    _log.debug("SAML Status Code 2:         #{idp_saml_response_status_code2 || 'None'}")
    _log.debug("SAML Status Message:        #{idp_saml_response_status_msg || 'None'}")
    _log.debug("SAML Status Detail:         #{idp_saml_response_status_detail || 'None'}")
    _log.debug("idp_assertion_consumer_url: #{@idp_assertion_consumer_url || 'None'}")
    _log.debug("idp_request_authenticated:  #{idp_request_authenticated || 'None'}")
    _log.debug("SAML Response:\n%s\n        #{@idp_saml_response_xml.to_s}")
    _log.debug("=== End Log IdP SOAP Response Info ===\n")
  end

  def log_paos_request(paos_request_xml)
    provider_name        = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/ecp:Request/@ProviderName')
    sp_is_passive        = get_xml_element_text(paos_request_xml, false, '/soap:Envelope/soap:Header/ecp:Request/@IsPassive')
    sp_issuer            = get_xml_element_text(paos_request_xml, true,  '/soap:Envelope/soap:Header/ecp:Request/saml:Issuer')
    sp_authn_request_xml = get_xml_element(paos_request_xml,      true,  '/soap:Envelope/soap:Body/samlp:AuthnRequest')

    _log.debug("\n=== Log PAOS request from SP ===")
    _log.debug("sp_response_consumer_url #{@sp_response_consumer_url || 'None'}")
    _log.debug("sp_message_id            #{@sp_message_id || 'None'}")
    _log.debug("sp_relay_state           #{@sp_relay_state || 'None'}")
    _log.debug("provider_name            #{provider_name || 'None'}")
    _log.debug("sp_is_passive            #{sp_is_passive || 'None'}")
    _log.debug("sp_issuer                #{sp_issuer || 'None'}")
    _log.debug("sp_authn_request_xml     #{sp_authn_request_xml || 'None'}")
    _log.debug("=== End Log PAOS request from SP ===\n")
  end

  def log_user_attrs(user_attrs)
    return unless _log.debug?

    user_attrs.each { |n,v| _log.debug("    #{n.ljust(20)} #{v}") }
  end

  def pp_xml_to_string(root) # format_xml_from_object
    root.to_s
  end
end
