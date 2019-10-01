require 'builder'
require 'saml_idp/service_provider'

module SamlIdp
  class SignatureBuilder
    attr_accessor :signed_info_builder, :audience_service_provider

    def initialize(signed_info_builder, audience_service_provider)
      self.signed_info_builder = signed_info_builder
      self.audience_service_provider = audience_service_provider
    end

    def raw
      builder = Builder::XmlMarkup.new
      builder.tag! "ds:Signature", "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#" do |signature|
        signature << signed_info
        signature.tag! "ds:SignatureValue", signature_value
        signature.KeyInfo xmlns: "http://www.w3.org/2000/09/xmldsig#" do |key_info|
          key_info.tag! "ds:X509Data" do |x509|
            x509.tag! "ds:X509Certificate", x509_certificate
          end
        end
      end
    end

    def service_provider
      @_service_provider ||=
        ServiceProvider.new(
          (service_provider_finder[audience_service_provider] || {})
        )
    end

    def x509_certificate
      extract_x509_certificate(certificate_by_provider)
    end
    private :x509_certificate

    def certificate_by_provider
      if service_provider.new_cert?
        SamlIdp.config.new_x509_certificate
      else
        SamlIdp.config.x509_certificate
      end
    end

    private def extract_x509_certificate(cert)
      return if cert.blank?

      cert
      .to_s
      .gsub(/-----BEGIN CERTIFICATE-----/,"")
      .gsub(/-----END CERTIFICATE-----/,"")
      .gsub(/\n/, "")
    end

    def signed_info
      signed_info_builder.raw
    end
    private :signed_info

    def signature_value
      signed_info_builder.signed
    end
    private :signature_value

    def service_provider_finder
      SamlIdp.config.service_provider.finder
    end
    private :service_provider_finder
  end
end
