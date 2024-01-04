# encoding: utf-8
require 'ostruct'
require 'securerandom'

module SamlIdp
  class IdPConfig
    IDP_REQUIRED_ATTR = [
      :entity_id,
      :audience_uri,
      :issuer_uri,
      :saml_acs_url,
      :x509_certificate,
      :secret_key,
      :password,
      :organization_name,
      :organization_url,
      :attribute_service_location,
      :single_service_post_location,
      :single_service_redirect_location,
      :single_logout_service_post_location,
      :single_logout_service_redirect_location
    ].freeze

    IDP_OPTIONAL_ATTR = [
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
      :compress
    ].freeze

    ALL_ATTRIBUTES = (IDP_REQUIRED_ATTR + IDP_OPTIONAL_ATTR).freeze

    DEFAULT_VALUES = {
      encryption: nil,
      signed_message: false,
      signed_assertion: true,
      compress: false,
      algorithm: :sha256,
      authn_context_classref: Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD,
      attributes: {},
      session_expiry: 0,
      expiry: 60 * 60
    }.freeze

    attr_reader(*ALL_ATTRIBUTES)

    def initialize(attributes = {})
      check_required_attributes(attributes)

      ALL_ATTRIBUTES.each do |attr|
        instance_variable_set("@#{attr}", attributes.key?(attr) ? attributes[attr] : DEFAULT_VALUES[attr])
      end

      self.reference_id ||= SecureRandom.uuid
      self.response_id ||= SecureRandom.uuid
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

    private

    def check_required_attributes(attributes)
      missing_attributes = IDP_REQUIRED_ATTR - attributes.keys
      raise ArgumentError, "Missing required attributes: #{missing_attributes.join(', ')}" unless missing_attributes.empty?
    end
  end
end
