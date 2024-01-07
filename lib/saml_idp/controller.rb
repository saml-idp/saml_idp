require 'openssl'
require 'base64'
require 'time'
require 'securerandom'
require 'saml_idp/request'
require 'saml_idp/logout_response_builder'
module SamlIdp
  module Controller
    extend ActiveSupport::Concern

    included do
      helper_method :saml_acs_url if respond_to? :helper_method
    end

    attr_accessor :algorithm

    protected

    def saml_request
      @saml_request ||= Struct.new(:request_id) do
        def authn_request?
          true
        end

        def issuer
          nil
        end

        def acs_url
          nil
        end
      end.new(nil)
    end

    def validate_saml_request(raw_saml_request = params[:SAMLRequest])
      decode_request(raw_saml_request)
      return true if valid_saml_request?

      head :forbidden if defined?(::Rails)
      false
    end

    def decode_request(raw_saml_request)
      @saml_request = Request.from_deflated_request(raw_saml_request, sp_config)
    end

    def authn_context_classref
      SamlIdp::XML::Namespaces::AuthnContext::ClassRef::PASSWORD
    end

    def encode_authn_response(principal)
      idp_config.load_saml_request(saml_request)
      SamlIdp::SamlResponse.new(
        principal: principal,
        idp_config: idp_config,
        saml_request: saml_request
      ).build
    end

    def encode_logout_response(_principal)
      SamlIdp::LogoutResponseBuilder.new(
        idp_config: idp_config,
        saml_request: saml_request,
      ).signed
    end

    def encode_response(principal, opts = {})
      if saml_request.authn_request?
        encode_authn_response(principal, opts)
      elsif saml_request.logout_request?
        encode_logout_response(principal, opts)
      else
        raise "Unknown request: #{saml_request}"
      end
    end

    def valid_saml_request?
      saml_request.valid?
    end

    def sp_config
      @sp_config ||= if sp_config_hash.present?
        SamlIdp::SpConfig.new(sp_config_hash)
      elsif sp_raw_metadata.present?
        SamlIdp::SpConfig.load_from_sp_metadata(sp_raw_metadata)
      else
        raise "Missing SP configuration"
      end
    end

    def sp_config_hash
      nil
    end

    def sp_raw_metadata
      nil
    end 

    def idp_config_hash
      raise "Missing IdP configuration"
    end

    def idp_config
      @idp_config ||= SamlIdp::IdPConfig.new(idp_config_hash)
    end

    def idp_metadata
      @idp_metadata ||= MetadataBuilder.new(idp_config)
    end
  end
end
