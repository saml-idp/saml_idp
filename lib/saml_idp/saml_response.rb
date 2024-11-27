# frozen_string_literal: true

require 'saml_idp/assertion_builder'
require 'saml_idp/response_builder'
module SamlIdp
  class SamlResponse
    attr_accessor :reference_id
    attr_accessor :response_id
    attr_accessor :issuer_uri
    attr_accessor :principal
    attr_accessor :audience_uri
    attr_accessor :saml_request_id
    attr_accessor :saml_acs_url
    attr_accessor :algorithm
    attr_accessor :private_key
    attr_accessor :pv_key_password
    attr_accessor :public_cert
    attr_accessor :authn_context_classref
    attr_accessor :expiry
    attr_accessor :encryption_opts
    attr_accessor :session_expiry
    attr_accessor :name_id_formats_opts
    attr_accessor :asserted_attributes_opts
    attr_accessor :signed_message_opts
    attr_accessor :signed_assertion_opts
    attr_accessor :compression_opts

    def initialize(
      reference_id:,
      response_id:,
      issuer_uri:,
      principal:,
      audience_uri:,
      saml_request_id:,
      saml_acs_url:,
      algorithm:,
      authn_context_classref:,
      public_cert:,
      private_key:,
      pv_key_password:,
      expiry: 60 * 60,
      encryption_opts: nil,
      session_expiry: 0,
      name_id_formats_opts: nil,
      asserted_attributes_opts: nil,
      signed_message_opts: false,
      signed_assertion_opts: true,
      compression_opts: false
    )

      self.reference_id = reference_id
      self.response_id = response_id
      self.issuer_uri = issuer_uri
      self.principal = principal
      self.audience_uri = audience_uri
      self.saml_request_id = saml_request_id
      self.saml_acs_url = saml_acs_url
      self.algorithm = algorithm
      self.private_key = private_key
      self.pv_key_password = pv_key_password
      self.public_cert = public_cert
      self.authn_context_classref = authn_context_classref
      self.expiry = expiry
      self.encryption_opts = encryption_opts
      self.session_expiry = session_expiry
      self.signed_message_opts = signed_message_opts
      self.name_id_formats_opts = name_id_formats_opts
      self.asserted_attributes_opts = asserted_attributes_opts
      self.signed_assertion_opts = signed_assertion_opts
      self.name_id_formats_opts = name_id_formats_opts
      self.asserted_attributes_opts = asserted_attributes_opts
      self.compression_opts = compression_opts
    end

    def build
      @build ||= encoded_message
    end

    def signed_assertion
      if encryption_opts
        assertion_builder.encrypt(sign: true)
      elsif signed_assertion_opts
        assertion_builder.signed
      else
        assertion_builder.raw
      end
    end

    private

    def encoded_message
      if signed_message_opts
        response_builder.encoded(signed_message: true, compress: compression_opts)
      else
        response_builder.encoded(signed_message: false, compress: compression_opts)
      end
    end

    def response_builder
      ResponseBuilder.new(
        response_id: response_id,
        issuer_uri: issuer_uri,
        saml_acs_url: saml_acs_url,
        saml_request_id: saml_request_id,
        assertion_and_signature: signed_assertion,
        raw_algorithm: algorithm,
        public_cert: public_cert,
        private_key: private_key,
        pv_key_password: pv_key_password,
      )
    end

    def assertion_builder
      @assertion_builder ||=
        AssertionBuilder.new(
          reference_id: (reference_id || SecureRandom.uuid),
          issuer_uri: issuer_uri,
          principal: principal,
          audience_uri: audience_uri,
          saml_request_id: saml_request_id,
          saml_acs_url: saml_acs_url,
          raw_algorithm: algorithm,
          authn_context_classref: authn_context_classref,
          public_cert: public_cert,
          private_key: private_key,
          pv_key_password: pv_key_password,
          expiry: expiry,
          encryption_opts: encryption_opts,
          session_expiry: session_expiry,
          name_id_formats_opts: name_id_formats_opts,
          asserted_attributes_opts: asserted_attributes_opts
        )
    end
  end
end
