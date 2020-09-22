require "ostruct"
module SamlIdp
  class Configurator
    attr_accessor :x509_certificate, :secret_key, :password, :algorithm, :organization_name, :organization_url, :base_saml_location, :entity_id, :reference_id_generator, :attribute_service_location, :single_service_post_location, :single_logout_service_post_location, :single_logout_service_redirect_location, :attributes, :service_provider, :assertion_consumer_service_hosts, :session_expiry

    def initialize(service_provider_config)
      if service_provider_config.present?
        service_providers = generate_service_provider_config(service_provider_config)
        self.x509_certificate = service_provider_config.certificate.x509
        self.secret_key = service_provider_config.certificate.private_key
        name_id.formats = {
          persistent: ->(principal) { principal.id }
        }
        self.service_provider = OpenStruct.new
        service_provider.finder = lambda { |issuer_or_entity_id|
          service_providers[issuer_or_entity_id]
        }
        self.algorithm = :sha1
        service_provider.metadata_persister = ->(id, settings) {}
        service_provider.persisted_metadata_getter = ->(id, service_provider) {}
        self.session_expiry = 0
        self.attributes = generate_attributes
      else
        self.x509_certificate = Default::X509_CERTIFICATE
        self.secret_key = Default::SECRET_KEY
        self.algorithm = :sha1
        self.reference_id_generator = -> { UUID.generate }
        self.service_provider = OpenStruct.new
        self.service_provider.finder = ->(_) { Default::SERVICE_PROVIDER }
        self.service_provider.metadata_persister = ->(id, settings) {}
        self.service_provider.persisted_metadata_getter = ->(id, service_provider) {}
        self.session_expiry = 0
        self.attributes = {}
      end
    end

    def generate_service_provider_config(service_provider)
      { service_provider.uuid.to_s => {
        "response_hosts" => [service_provider.callback_url],
        "metadata_url"   => service_provider.callback_url
      } }
    end

    def generate_attributes
      {
        "Email address" => {
          "name" => "email",
          "name_format" => "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
          "getter" => ->(principal) { principal.email }
        },
        "First Name" => {
          "name" => "firstName",
          "name_format" => "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
          "getter" => ->(principal) { principal.first_name }
        },
        "Last Name" => {
          "name" => "lastName",
          "name_format" => "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
          "getter" => ->(principal) { principal.last_name }
        }
      }
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
  end
end
