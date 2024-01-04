require 'net/http'
require 'uri'
require 'saml_idp/attributeable'
require 'saml_idp/sp_metadata'
module SamlIdp
  class SpConfig
    include Attributeable
    attribute :entity_id
    attribute :cert
    attribute :fingerprint
    attribute :fingerprint_algorithm
    attribute :validate_signature
    attribute :acs_url
    attribute :assertion_consumer_logout_service_url
    attribute :response_hosts
    attribute :sp_metadata

    def self.load_from_sp_metadata(raw_xml)
      metadata = SamlIdp::SpMetadata.new(raw_xml)
      metadata_hash = metadata.to_h
      new(
        sp_metadata: metadata,
        entity_id: metadata_hash[:entity_id],
        cert: metadata_hash[:signing_certificate],
        acs_url: metadata_hash[:assertion_consumer_services].first,
        assertion_consumer_logout_service_url: metadata_hash[:single_logout_services]&.first
      )
    end

    def valid?
      attributes.present?
    end

    def valid_signature?(doc, require_signature = false)
      if require_signature || attributes[:validate_signature]
        doc.valid_signature?(fingerprint)
      else
        true
      end
    end

    def acceptable_response_hosts
      Array(self.response_hosts)
    end

    def fingerprint
      sha_size = fingerprint_algorithm || :sha256
      @fingerprint ||= SamlIdp::Fingerprint.certificate_digest(cert, sha_size)
    end

    def response_hosts
      sp_metadata.assertion_consumer_services.map do |acs|
        url = acs['location'] || acs[:location]
        URI(url).host
      end
    end

    def acs_url
      sp_metadata.saml_acs_url
    end

    def cert
      @cert ||= sp_metadata.signing_certificate
    end
  end
end
