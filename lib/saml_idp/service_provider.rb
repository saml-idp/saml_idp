require 'net/http'
require 'uri'
require 'saml_idp/attributeable'
require 'saml_idp/incoming_metadata'
require 'saml_idp/persisted_metadata'
module SamlIdp
  class ServiceProvider
    include Attributeable
    attribute :identifier
    attribute :cert
    attribute :fingerprint
    attribute :metadata_url
    attribute :validate_signature
    attribute :sign_authn_request
    attribute :acs_url
    attribute :assertion_consumer_logout_service_url
    attribute :response_hosts

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

    def refresh_metadata
      fresh = fresh_incoming_metadata
      if valid_signature?(fresh.document)
        metadata_persister[identifier, fresh]
        @current_metadata = nil
        fresh
      end
    end

    def current_metadata
      @current_metadata ||= get_current_or_build
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

    def get_current_or_build
      persisted = metadata_getter[identifier, self]
      if persisted.is_a? Hash
        PersistedMetadata.new(persisted)
      end
    end
    private :get_current_or_build

    def metadata_getter
      config.service_provider.persisted_metadata_getter
    end
    private :metadata_getter

    def metadata_persister
      config.service_provider.metadata_persister
    end
    private :metadata_persister

    def fresh_incoming_metadata
      IncomingMetadata.new request_metadata
    end
    private :fresh_incoming_metadata

    def request_metadata
      metadata_url.present? ? Net::HTTP.get(URI.parse(metadata_url)) : ""
    end
    private :request_metadata
  end
end
