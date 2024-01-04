# frozen_string_literal: true

require 'saml_idp/assertion_builder'
require 'saml_idp/response_builder'
module SamlIdp
  class SamlResponse
    attr_accessor :principal, :idp_config, :saml_request

    def initialize(principal:, idp_config:, saml_request:)
      self.principal = principal
      self.idp_config = idp_config
      self.saml_request = saml_request
    end

    def build
      @build ||= encoded_message
    end

    def signed_assertion
      if idp_config.encryption
        assertion_builder.encrypt(sign: true)
      elsif idp_config.signed_assertion
        assertion_builder.signed
      else
        assertion_builder.raw
      end
    end
    private :signed_assertion

    def encoded_message
      response_builder.encoded(signed_message: idp_config.signed_message, compress: idp_config.compression)
    end
    private :encoded_message

    def response_builder
      
      ResponseBuilder.new(
        response_id: idp_config.response_id,
        issuer_uri: idp_config.issuer_uri,
        saml_acs_url: idp_config.saml_acs_url,
        saml_request_id: saml_request.request_id,
        assertion_and_signature: idp_config.assertion_and_signature,
        raw_algorithm: idp_config.raw_algorithm
      )
    end
    private :response_builder

    def assertion_builder
      @assertion_builder ||= AssertionBuilder.new(
        reference_id: SecureRandom.uuid,
        issuer_uri: idp_config.issuer_uri,
        principal: principal,
        audience_uri: idp_config.audience_uri,
        saml_request_id: saml_request.request_id,
        saml_acs_url: idp_config.saml_acs_url,
        raw_algorithm: idp_config.raw_algorithm,
        authn_context_classref:  idp_config.authn_context_classref,
        expiry: idp_config.expiry,
        encryption_opts: idp_config.encryption_opts,
        session_expiry: idp_config.session_expiry,
        name_id_formats_opts: idp_config.name_id_formats_opts,
        asserted_attributes_opts: idp_config.asserted_attributes_opts
      )
    end
    private :assertion_builder
  end
end
