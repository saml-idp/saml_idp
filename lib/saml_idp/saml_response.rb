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
    attr_accessor :secret_key
    attr_accessor :x509_certificate
    attr_accessor :authn_context_classref
    attr_accessor :expiry
    attr_accessor :encryption_opts
    attr_accessor :session_expiry
    attr_accessor :name_id_formats_opts
    attr_accessor :asserted_attributes_opts
    attr_accessor :signed_message_opts
    attr_accessor :signed_assertion_opts

    def initialize(
      reference_id,
      response_id,
      issuer_uri,
      principal,
      audience_uri,
      saml_request_id,
      saml_acs_url,
      algorithm,
      authn_context_classref,
      expiry = 60 * 60,
      encryption_opts = nil,
      session_expiry = 0,
      signed_message_opts = false,
      signed_assertion_opts = true,
      name_id_formats_opts = nil,
      asserted_attributes_opts = nil
    )

      self.reference_id = reference_id
      self.response_id = response_id
      self.issuer_uri = issuer_uri
      self.principal = principal
      self.audience_uri = audience_uri
      self.saml_request_id = saml_request_id
      self.saml_acs_url = saml_acs_url
      self.algorithm = algorithm
      self.secret_key = secret_key
      self.x509_certificate = x509_certificate
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
    private :signed_assertion

    def encoded_message
      if signed_message_opts
        response_builder.encoded(signed_message: true, compress: compression_opts)
      else
        response_builder.encoded(signed_message: false, compress: compression_opts)
      end
    end
    private :encoded_message

    def response_builder
      ResponseBuilder.new(response_id, issuer_uri, saml_acs_url, saml_request_id, signed_assertion, algorithm)
    end
    private :response_builder

    def assertion_builder
      @assertion_builder ||=
        AssertionBuilder.new reference_id,
                             issuer_uri,
                             principal,
                             audience_uri,
                             saml_request_id,
                             saml_acs_url,
                             algorithm,
                             authn_context_classref,
                             expiry,
                             encryption_opts,
                             session_expiry,
                             name_id_formats_opts,
                             asserted_attributes_opts
    end
    private :assertion_builder
  end
end
