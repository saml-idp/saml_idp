require 'net/http'
require 'uri'
require 'saml_idp/attributeable'
require 'saml_idp/sp_metadata'
module SamlIdp
  class ServiceProvider
    include Attributeable
    attribute :identifier
    attribute :cert
    attribute :fingerprint
    attribute :metadata_url
    attribute :validate_signature
    attribute :acs_url
    attribute :assertion_consumer_logout_service_url
    attribute :response_hosts
    attribute :sp_metadata

    delegate :config, to: :SamlIdp

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

    def current_metadata
      @current_metadata ||= sp_metadata
    end

    def acceptable_response_hosts
      hosts = Array(self.response_hosts)
      hosts.push(metadata_url_host) if metadata_url_host

      hosts
    end

    def metadata_url_host
      if metadata_url.present?
        URI(metadata_url).host
      end
    end

    def fingerprint
      @fingerprint ||= SamlIdp::Fingerprint.certificate_digest(cert)
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
