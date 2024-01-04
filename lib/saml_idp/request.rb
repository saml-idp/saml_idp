require 'saml_idp/xml_security'
require 'saml_idp/sp_config'
require 'logger'
module SamlIdp
  class Request
    def self.from_deflated_request(raw, sp_config)
      if raw
        decoded = Base64.decode64(raw)
        zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        begin
          inflated = zstream.inflate(decoded).tap do
            zstream.finish
            zstream.close
          end
        rescue Zlib::BufError, Zlib::DataError # not compressed
          inflated = decoded
        end
      else
        inflated = ""
      end
      new(inflated, sp_config)
    end

    attr_accessor :raw_xml, :sp_config, :error_msg

    delegate :config, to: :SamlIdp
    private :config
    delegate :xpath, to: :document
    private :xpath

    def initialize(raw_xml = "", sp_config)
      self.raw_xml = raw_xml
      self.sp_config = sp_config
      self.error_msg = ""
    end

    def logout_request?
      logout_request.nil? ? false : true
    end

    def authn_request?
      authn_request.nil? ? false : true
    end

    def request_id
      request["ID"]
    end

    def request
      if authn_request?
        authn_request
      elsif logout_request?
        logout_request
      end
    end

    def requested_authn_context
      if authn_request? && authn_context_node
        authn_context_node.content
      else
        nil
      end
    end

    def acs_url
      authn_request["AssertionConsumerServiceURL"].to_s || sp_config.acs_url
    end

    def logout_url
      sp_config.assertion_consumer_logout_service_url
    end

    def response_url
      if authn_request?
        acs_url
      elsif logout_request?
        logout_url
      end
    end

    def valid?
      unless sp_config?
        @error_msg = "Unable to find service provider for issuer #{issuer}"
        return false
      end

      unless (authn_request? ^ logout_request?)
        @error_msg = "One and only one of authnrequest and logout request is required. authnrequest: #{authn_request?} logout_request: #{logout_request?} "
        return false
      end

      unless valid_signature?
        @error_msg = "Signature is invalid in #{raw_xml}"
        return false
      end

      if response_url.nil?
        @error_msg = "Unable to find response url for #{issuer}: #{raw_xml}"
        return false
      end

      if !sp_config.acceptable_response_hosts.include?(response_host)
        @error_msg = "#{sp_config.acceptable_response_hosts} compare to #{response_host}"
        @error_msg = "No acceptable AssertionConsumerServiceURL, request AssertionConsumerServiceURL should include in SP metadata"
        return false
      end

      return true
    end

    def valid_signature?
      # Force signatures for logout requests because there is no other protection against a cross-site DoS.
      # Validate signature when metadata specify AuthnRequest should be signed
      metadata = sp_config.current_metadata
      if logout_request? || authn_request? && metadata.respond_to?(:sign_authn_request?) && metadata.sign_authn_request?
        document.valid_signature?(sp_config.fingerprint)
      else
        true
      end
    end

    def sp_config?
      sp_config && sp_config.valid?
    end

    def issuer
      @_issuer ||= xpath("//saml:Issuer", saml: assertion).first.try(:content)
      @_issuer if @_issuer.present?
    end

    def name_id
      @_name_id ||= xpath("//saml:NameID", saml: assertion).first.try(:content)
    end

    def session_index
      @_session_index ||= xpath("//samlp:SessionIndex", samlp: samlp).first.try(:content)
    end

    def response_host
      uri = URI(response_url)
      if uri
        uri.host
      end
    end
    private :response_host

    def document
      @_document ||= Saml::XML::Document.parse(raw_xml)
    end
    private :document

    def authn_context_node
      @_authn_context_node ||= xpath("//samlp:AuthnRequest/samlp:RequestedAuthnContext/saml:AuthnContextClassRef",
        samlp: samlp,
        saml: assertion).first
    end
    private :authn_context_node

    def authn_request
      @_authn_request ||= xpath("//samlp:AuthnRequest", samlp: samlp).first
    end
    private :authn_request

    def logout_request
      @_logout_request ||= xpath("//samlp:LogoutRequest", samlp: samlp).first
    end
    private :logout_request

    def samlp
      Saml::XML::Namespaces::PROTOCOL
    end
    private :samlp

    def assertion
      Saml::XML::Namespaces::ASSERTION
    end
    private :assertion

    def signature_namespace
      Saml::XML::Namespaces::SIGNATURE
    end
    private :signature_namespace
  end
end
