require 'saml_idp/xml_security'
require 'saml_idp/service_provider'
require 'saml_idp/authn_request'
require 'saml_idp/single_logout_request'
module SamlIdp
  class Request
    attr_accessor :raw_xml, :service_provider

    delegate :config, to: :SamlIdp
    private :config
    delegate :xpath, to: :document
    private :xpath

    def initialize(saml_request = "", service_provider)
      self.raw_xml = from_deflated_request(saml_request)
      self.service_provider = service_provider
    end

    def logout_request?
      @logout_request_doc ||= xpath("//samlp:LogoutRequest", samlp: samlp).first
      @logout_request_doc.nil? ? false : true
    end

    def authn_request?
      @authn_request_doc ||= xpath("//samlp:AuthnRequest", samlp: samlp).first
      @authn_request_doc.nil? ? false : true
    end

    def request
      if authn_request?
        @authn_request_doc
      elsif logout_request?
        @logout_request_doc
      end
    end

    def requested_authn_context
      if authn_request? && authn_request.authn_context_node
        authn_request.authn_context_node.content
      else
        nil
      end
    end

    def request_id
      request["ID"]
    end

    def version
      request["Version"]
    end

    def issue_instant
      request["IssueInstant"]
    end

    def destination
      request["Destination"]
    end

    def issuer
      @_issuer ||= xpath("//saml:Issuer", saml: assertion).first.try(:content)
      @_issuer if @_issuer.present?
    end

    def response_url
      if authn_request?
        authn_request.acs_url
      elsif logout_request?
        true # SLO doesn't have specification override SLO url
      end
    end

    def errors
      @errors ||= []
    end

    def valid?
      # Unable to find service provider from request
      unless service_provider_info.present?
        errors.push(:no_sp_id)
        return false
      end

      # ID must be used for SAML response
      unless request_id.present?
        errors.push(:no_request_id)
        return false
      end

      unless version.present?
        errors.push(:no_version)
        return false
      end

      unless issue_instant.present?
        errors.push(:no_issue_instant)
        return false
      end

      # One and only one of authnrequest and logout request is required. authnrequest or logout_request
      if !(authn_request? || logout_request?)
        errors.push(:unknown_request)
        return false
      end

      # Signature is invalid in SAML Request
      unless valid_signature?
        errors.push(:invalid_signature)
        return false
      end

      # Unable to find response url for #{issuer}: #{raw_xml}
      if response_url.nil?
        return false
      end

      # Authn Request specific validation
      if authn_request? && !authn_request.valid?
        errors.concat(authn_request.errors)
      end

      # SLO Request specific validation
      if logout_request? && !logout_request.valid?
        errors.concat(logout_request.errors)
      end

      return true
    end

    def valid_signature?
      # Force signatures for logout requests because there is no other protection against a cross-site DoS.
      # Validate signature when metadata specify AuthnRequest should be signed
      metadata = service_provider.current_metadata
      if logout_request? || authn_request? && metadata.respond_to?(:sign_authn_request?) && metadata.sign_authn_request?
        document.valid_signature?(service_provider.fingerprint)
      else
        true
      end
    end

    def service_provider_info
      issuer || 
      authn_request? && authn_request.provider_name || 
      logout_request? && logout_request.sp_name_qualifier ||
      destination.present? && destination
    end

    def document
      @_document ||= Saml::XML::Document.parse(raw_xml)
    end
    private :document

    def authn_request
      @_authn_request ||= AuthnRequest.new(raw_xml, sp_config)
    end
    private :authn_request

    def logout_request
      @_logout_request ||= SingleLogoutRequest.new(raw_xml, sp_config)
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

    def from_deflated_request(raw)
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
      inflated
    end
    private :from_deflated_request
  end
end
