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
      @saml_request ||= Struct.new(
        :request_id,
        :issue_url,
        :acs_url
      ) do
        def authn_request?
          true
        end

        def idp_initiated?
          true
        end

        def issuer
          url = URI(issue_url)
          url.query = nil
          url.to_s
        end
      end.new(nil, idp_config.issuer_uri, sp_config.assertion_consumer_services.first[:location])
    end

    def validate_saml_request
      decode_request
      return true if valid_saml_request?

      head :forbidden if defined?(::Rails)
      false
    end

    def decode_request
      @saml_request ||= Request.from_deflated_request(raw_saml_request, sp_config)
      sp_config.load_saml_request(@saml_request)
    end

    def encode_authn_response(principal)
      SamlIdp::SamlResponse.new(
        principal: principal,
        idp_config: idp_config,
        sp_config: sp_config,
        saml_request: saml_request
      ).build
    end

    def encode_logout_response(_principal)
      SamlIdp::LogoutResponseBuilder.new(
        idp_config: idp_config,
        saml_request: saml_request,
      ).signed
    end

    def encode_response(principal)
      if saml_request.authn_request?
        encode_authn_response(principal)
      elsif saml_request.logout_request?
        encode_logout_response(principal)
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

    def raw_saml_request
      raise "Missing SAML SP initiated request getter implementation"
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
