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
      @saml_request = Request.from_deflated_request(raw_saml_request)
    end

    def authn_context_classref
      Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD
    end

    def encode_authn_response(principal, opts = {})
      response_id = get_saml_response_id
      reference_id = opts[:reference_id] || get_saml_reference_id
      audience_uri = opts[:audience_uri] || audience_uri
      opt_issuer_uri = opts[:issuer_uri] || issuer_uri
      my_authn_context_classref = opts[:authn_context_classref] || authn_context_classref
      acs_url = opts[:acs_url] || saml_acs_url
      expiry = opts[:expiry] || 60*60
      session_expiry = opts[:session_expiry]
      encryption_opts = opts[:encryption] || nil
      name_id_formats_opts = opts[:name_id_formats] || nil
      asserted_attributes_opts = opts[:attributes] || nil
      signed_message_opts = opts[:signed_message] || false
      name_id_formats_opts = opts[:name_id_formats] || nil
      asserted_attributes_opts = opts[:attributes] || nil
      signed_assertion_opts = opts[:signed_assertion] || true
      compress_opts = opts[:compress] || false

      SamlResponse.new(
        reference_id,
        response_id,
        opt_issuer_uri,
        principal,
        audience_uri,
        saml_request_id,
        acs_url,
        (opts[:algorithm] || algorithm || default_algorithm),
        my_authn_context_classref,
        expiry,
        encryption_opts,
        session_expiry,
        name_id_formats_opts,
        asserted_attributes_opts,
        signed_message_opts,
        signed_assertion_opts,
        compress_opts
      ).build
    end

    def encode_logout_response(opts = {})
      SamlIdp::LogoutResponseBuilder.new(
        get_saml_response_id,
        (opts[:issuer_uri] || issuer_uri),
        saml_logout_url,
        saml_request_id,
        (opts[:algorithm] || algorithm || default_algorithm)
      ).signed
    end

    def encode_response(principal, type, opts = {})
      if type == :auth
        encode_authn_response(principal, opts)
      elsif type == :logout
        encode_logout_response(opts)
      else
        raise "Unknown request: #{type}"
      end
    end

    def issuer_uri
      (SamlIdp.config.base_saml_location.present? && SamlIdp.config.base_saml_location) ||
        (defined?(request) && request.url.to_s.split("?").first) ||
        "http://example.com"
    end

    def audience_uri
      SamlIdp.config.service_provider
    end

    def valid_saml_request?
      saml_request.valid?
    end

    def saml_request_id
      saml_request.request_id
    end

    def saml_acs_url
      saml_request.acs_url
    end

    def saml_logout_url
      saml_request.logout_url
    end

    def get_saml_response_id
      SecureRandom.uuid
    end

    def get_saml_reference_id
      SecureRandom.uuid
    end

    def default_algorithm
      OpenSSL::Digest::SHA256
    end
  end
end
