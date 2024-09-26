require 'saml_idp/xml_security'
require 'saml_idp/service_provider'
require 'logger'
module SamlIdp
  class Request
    def self.from_deflated_request(raw, external_attributes = {})
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
      new(inflated, external_attributes)
    end

    attr_accessor :raw_xml, :saml_request, :signature, :sig_algorithm, :relay_state

    delegate :config, to: :SamlIdp
    private :config
    delegate :xpath, to: :document
    private :xpath

    def initialize(raw_xml = "", external_attributes = {})
      self.raw_xml = raw_xml
      self.saml_request = external_attributes[:saml_request]
      self.relay_state = external_attributes[:relay_state]
      self.sig_algorithm = external_attributes[:sig_algorithm]
      self.signature = external_attributes[:signature]
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
      service_provider.acs_url ||
        authn_request["AssertionConsumerServiceURL"].to_s
    end

    def logout_url
      service_provider.assertion_consumer_logout_service_url
    end

    def response_url
      if authn_request?
        acs_url
      elsif logout_request?
        logout_url
      end
    end

    def log(msg)
      if config.logger.respond_to?(:call)
        config.logger.call msg
      else
        config.logger.info msg
      end
    end

    def valid?(external_attributes = {})
      unless service_provider?
        log "Unable to find service provider for issuer #{issuer}"
        return false
      end

      unless (authn_request? ^ logout_request?)
        log "One and only one of authnrequest and logout request is required. authnrequest: #{authn_request?} logout_request: #{logout_request?} "
        return false
      end

      # XML embedded signature
      if signature.nil? && !valid_signature?
        log "Requested document signature is invalid in #{raw_xml}"
        return false
      end

      # URI query signature
      if signature.present? && !valid_external_signature?
        log "Requested URI signature is invalid in #{raw_xml}"
        return false
      end

      if response_url.nil?
        log "Unable to find response url for #{issuer}: #{raw_xml}"
        return false
      end

      if !service_provider.acceptable_response_hosts.include?(response_host)
        log "#{service_provider.acceptable_response_hosts} compare to #{response_host}"
        log "No acceptable AssertionConsumerServiceURL, either configure them via config.service_provider.response_hosts or match to your metadata_url host"
        return false
      end

      return true
    end

    def valid_signature?
      # Force signatures for logout requests because there is no other protection against a cross-site DoS.
      # Validate signature when metadata specify AuthnRequest should be signed
      metadata = service_provider.current_metadata
      if logout_request? || authn_request? && metadata.respond_to?(:sign_authn_request?) && metadata.sign_authn_request?
        document.valid_signature?(service_provider.cert, service_provider.fingerprint)
      else
        true
      end
    end

    def valid_external_signature?
      cert = OpenSSL::X509::Certificate.new(service_provider.cert)

      sha_version = sig_algorithm =~ /sha(.*?)$/i && $1.to_i
      raw_signature = Base64.decode64(signature)

      signature_algorithm = case sha_version
      when 256 then OpenSSL::Digest::SHA256
      when 384 then OpenSSL::Digest::SHA384
      when 512 then OpenSSL::Digest::SHA512
      else
        OpenSSL::Digest::SHA1
      end

      cert.public_key.verify(signature_algorithm.new, raw_signature, query_request_string)
    end

    def service_provider?
      service_provider && service_provider.valid?
    end

    def service_provider
      return unless issuer.present?
      @_service_provider ||= ServiceProvider.new((service_provider_finder[issuer] || {}).merge(identifier: issuer))
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

    def query_request_string
      url_string = "SAMLRequest=#{CGI.escape(saml_request)}"
      url_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
      url_string << "&SigAlg=#{CGI.escape(sig_algorithm)}"
    end
    private :query_request_string

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

    def service_provider_finder
      config.service_provider.finder
    end
    private :service_provider_finder
  end
end
