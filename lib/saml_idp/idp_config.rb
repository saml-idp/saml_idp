# encoding: utf-8
require 'ostruct'
require 'securerandom'

module SamlIdp
  class IdPConfig
    IDP_REQUIRED_ATTR = [
      :base_url,
      :x509_certificate,
      :secret_key,
      :password,
      :name_id_formats,
      :single_service_post_location,
      :single_service_redirect_location,
    ].freeze

    IDP_OPTIONAL_ATTR = [
      :entity_id,
      :issuer_uri,
      :reference_id,
      :response_id,
      :raw_algorithm,
      :saml_attributes,
      :session_expiry,
      :authn_context_classref,
      :expiry,
      :encryption_config,
      :asserted_attributes,
      :signed_message,
      :signed_assertion,
      :compress,
      :single_logout_service_post_location,
      :single_logout_service_redirect_location,
      :attribute_service_location,
      :organization_name,
      :organization_url
    ].freeze

    ALL_ATTRIBUTES = (IDP_REQUIRED_ATTR + IDP_OPTIONAL_ATTR).freeze

    DEFAULT_VALUES = {
      encryption_config: nil,
      signed_message: false,
      signed_assertion: true,
      compress: false,
      raw_algorithm: :sha256,
      authn_context_classref: SamlIdp::XML::Namespaces::AuthnContext::ClassRef::PASSWORD,
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

      @reference_id ||= SecureRandom.uuid
      @response_id ||= SecureRandom.uuid
      @entity_id ||= @base_url
      @issuer_uri ||= @base_url
    end

    def single_logout_url
      single_logout_service_post_location || single_logout_service_redirect_location
    end

    def algorithm
      OpenSSL::Digest.const_get(raw_algorithm.to_s.upcase)
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

    def to_hash
      instance_variables.each_with_object({}) do |var, hash|
        hash[var.to_s.delete("@").to_sym] = instance_variable_get(var)
      end
    end

    def check_required_attributes(attributes)
      missing_attributes = IDP_REQUIRED_ATTR - attributes.keys
      raise ArgumentError, "Missing required attributes: #{missing_attributes.join(', ')}" unless missing_attributes.empty?
    end
    private :check_required_attributes
  end
end
