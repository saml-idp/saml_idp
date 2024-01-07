require 'net/http'
require 'uri'
require 'saml_idp/attributeable'
require 'saml_idp/sp_metadata'
module SamlIdp
  class SpConfig
    SP_REQUIRED_ATTR = [
      :entity_id,
      :assertion_consumer_services
    ].freeze

    SP_OPTIONAL_ATTR = [
      :fingerprint,
      :fingerprint_algorithm,
      :sign_assertions,
      :sign_authn_request,
      :signing_certificate,
      :encryption_certificate,
      :single_logout_services,
      :name_id_formats,
      :given_name,
      :display_name,
      :contact_person,
      :surname,
      :company,
      :telephone_number,
      :email_address,
      :role_descriptor_document,
      :service_provider_descriptor_document,
      :idp_descriptor_document,
      :contact_person_document
    ].freeze

    INTERNAL_ATTR = [
      :response_hosts,
      :sp_metadata
    ]

    ALL_ATTRIBUTES = (SP_REQUIRED_ATTR + SP_OPTIONAL_ATTR + INTERNAL_ATTR).freeze

    DEFAULT_VALUES = {
      sign_assertions: false,
      sign_authn_request: true,
      fingerprint_algorithm: :sha256,
    }.freeze

    attr_reader(*ALL_ATTRIBUTES)

    def self.load_from_sp_metadata(raw_xml)
      metadata = SamlIdp::SpMetadata.new(raw_xml)
      metadata_hash = metadata.to_h
      new(metadata_hash)
    end

    def initialize(attributes = {})
      check_required_attributes(attributes)

      ALL_ATTRIBUTES.each do |attr|
        instance_variable_set("@#{attr}", attributes.key?(attr) ? attributes[attr] : DEFAULT_VALUES[attr])
      end
    end

    def valid?
      (SP_REQUIRED_ATTR - to_hash.keys).empty?
    end

    def valid_signature?
      sp_metadata.document.valid_signature?(fingerprint)
    end

    def acceptable_response_hosts
      Array(self.response_hosts)
    end

    def fingerprint
      sha_size = fingerprint_algorithm || :sha256
      @fingerprint ||= SamlIdp::Fingerprint.certificate_digest(cert, sha_size)
    end

    def response_hosts
      assertion_consumer_services.map do |acs|
        url = acs['location'] || acs[:location]
        URI(url).host
      end
    end

    def to_hash
      instance_variables.each_with_object({}) do |var, hash|
        hash[var.to_s.delete("@").to_sym] = instance_variable_get(var)
      end
    end

    def check_required_attributes(attributes)
      missing_attributes = SP_REQUIRED_ATTR - attributes.keys
      raise ArgumentError, "Missing required attributes: #{missing_attributes.join(', ')}" unless missing_attributes.empty?
    end
    private :check_required_attributes
  end
end
