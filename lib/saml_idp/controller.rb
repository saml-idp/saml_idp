require 'openssl'
require 'base64'
require 'time'
require 'securerandom'
require 'saml_idp/request'
require 'saml_idp/logout_response_builder'
require 'saml_idp/logout_request_builder'

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
      decode_request(raw_saml_request, params[:Signature], params[:SigAlg], params[:RelayState])
      valid_saml_request?
    end

    def decode_request(raw_saml_request, signature, sig_algorithm, relay_state)
      @saml_request = Request.from_deflated_request(
        raw_saml_request,
        saml_request: raw_saml_request,
        signature: signature,
        sig_algorithm: sig_algorithm,
        relay_state: relay_state
      )
    end

    def authn_context_classref
      Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD
    end

    def encode_authn_response(principal, opts = {})
      response_id = get_saml_response_id
      reference_id = opts[:reference_id] || get_saml_reference_id
      audience_uri = opts[:audience_uri] || saml_request.issuer || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
      opt_issuer_uri = opts[:issuer_uri] || issuer_uri
      my_authn_context_classref = opts[:authn_context_classref] || authn_context_classref
      public_cert = opts[:public_cert] || SamlIdp.config.x509_certificate
      private_key = opts[:private_key] || SamlIdp.config.secret_key
      pv_key_password = opts[:pv_key_password] || SamlIdp.config.password
      acs_url = opts[:acs_url] || saml_acs_url
      expiry = opts[:expiry] || 60*60
      session_expiry = opts[:session_expiry]
      encryption_opts = opts[:encryption] || nil
      name_id_formats_opts = opts[:name_id_formats] || nil
      asserted_attributes_opts = opts[:attributes] || nil
      signed_message_opts = opts[:signed_message] || false
      name_id_formats_opts = opts[:name_id_formats] || nil
      asserted_attributes_opts = opts[:attributes] || nil
      signed_assertion_opts = opts[:signed_assertion].nil? ? true : opts[:signed_assertion]
      compress_opts = opts[:compress] || false

      SamlResponse.new(
        reference_id: reference_id,
        response_id: response_id,
        issuer_uri: opt_issuer_uri,
        principal: principal,
        audience_uri: audience_uri,
        saml_request_id: saml_request_id,
        saml_acs_url: acs_url,
        algorithm: (opts[:algorithm] || algorithm || default_algorithm),
        authn_context_classref: my_authn_context_classref,
        public_cert: public_cert,
        private_key: private_key,
        pv_key_password: pv_key_password,
        expiry: expiry,
        encryption_opts: encryption_opts,
        session_expiry: session_expiry,
        name_id_formats_opts: name_id_formats_opts,
        asserted_attributes_opts: asserted_attributes_opts,
        signed_message_opts: signed_message_opts,
        signed_assertion_opts: signed_assertion_opts,
        compression_opts: compress_opts
      ).build
    end

    def encode_logout_response(_principal, opts = {})
      SamlIdp::LogoutResponseBuilder.new(
        response_id: get_saml_response_id,
        issuer_uri: (opts[:issuer_uri] || issuer_uri),
        saml_slo_url: saml_logout_url,
        saml_request_id: saml_request_id,
        algorithm: (opts[:algorithm] || algorithm || default_algorithm),
        public_cert: opts[:public_cert] || SamlIdp.config.x509_certificate,
        private_key: opts[:private_key] || SamlIdp.config.secret_key,
        pv_key_password: opts[:pv_key_password] || SamlIdp.config.password
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

    def issuer_uri
      (SamlIdp.config.base_saml_location.present? && SamlIdp.config.base_saml_location) ||
        (defined?(request) && request.url.to_s.split("?").first) ||
        "http://example.com"
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
