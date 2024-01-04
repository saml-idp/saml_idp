# encoding: utf-8
require 'ostruct'
require 'securerandom'

module SamlIdp
  class IdPConfig
    IDP_ATTR = [
      :x509_certificate,
      :secret_key,
      :password,
      :organization_name,
      :organization_url,
      :issuer_uri,
      :audience_uri,
      :entity_id,
      :attribute_service_location,
      :single_service_post_location,
      :single_service_redirect_location,
      :single_logout_service_post_location,
      :single_logout_service_redirect_location,
      :saml_acs_url,
      :reference_id,
      :response_id,
      :algorithm,
      :attributes,
      :session_expiry,
      :authn_context_classref,
      :expiry,
      :encryption,
      :name_id_format,
      :asserted_attributes,
      :signed_message,
      :signed_assertion,
      :compress,
      :logger,
      :sp_config
    ].freeze
    attr_reader(*IDP_ATTR)

    def initialize(
      x509_certificate:,
      secret_key:,
      password:,
      organization_name:,
      organization_url:,
      issuer_uri:,
      audience_uri:,
      entity_id:,
      attribute_service_location:,
      single_service_post_location:,
      single_service_redirect_location:,
      single_logout_service_post_location:,
      single_logout_service_redirect_location:,
      saml_acs_url:,
      reference_id: nil,
      response_id: nil,
      algorithm: OpenSSL::Digest::SHA256,
      attributes: {},
      session_expiry: 0,
      authn_context_classref: Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD,
      expiry: 60*60,
      encryption: nil,
      name_id_format: nil,
      asserted_attributes: nil,
      signed_message: false,
      signed_assertion: true,
      compress: false,
      logger: nil,
      sp_config:
    )
      self.reference_id = reference_id || SecureRandom.uuid
      self.response_id = response_id || SecureRandom.uuid
      self.logger = defined?(::Rails) ? Rails.logger : ->(msg) { puts msg }
    end

    # formats
    # getter
    def name_id
      @name_id ||= OpenStruct.new
    end

    def technical_contact
      @technical_contact ||= TechnicalContact.new
    end

    class TechnicalContact < OpenStruct
      def mail_to_string
        "mailto:#{email_address}" if email_address.to_s.length > 0
      end
    end

    def load_saml_request(saml_request)
      self.audience_uri = idp_config.audience_uri || saml_request.issuer || saml_request.acs_url[/^(.*?\/\/.*?\/)/, 1]
      self.issuer_uri = idp_config.issuer_uri || saml_request.to_s.split("?").first || "http://example.com"
      self.acs_url = idp_config.acs_url || saml_request.acs_url
    end

    def to_hash
      instance_variables.each_with_object({}) do |var, hash|
        hash[var.to_s.delete("@").to_sym] = instance_variable_get(var)
      end
    end
  end
end
