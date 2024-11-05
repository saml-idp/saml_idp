require 'builder'

module SamlIdp
  class SignatureBuilder
    attr_accessor :signed_info_builder, :x509_certificate

    def initialize(signed_info_builder, x509_certificate)
      self.signed_info_builder = signed_info_builder
      self.x509_certificate = x509_certificate
    end

    def raw
      builder = Builder::XmlMarkup.new
      builder.tag! "ds:Signature", "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#" do |signature|
        signature << signed_info
        signature.tag! "ds:SignatureValue", signature_value
        signature.KeyInfo xmlns: "http://www.w3.org/2000/09/xmldsig#" do |key_info|
          key_info.tag! "ds:X509Data" do |x509|
            x509.tag! "ds:X509Certificate", der_certificate
          end
        end
      end
    end

    private

    def der_certificate
      certificate_formatter(x509_certificate)
    end

    def signed_info
      signed_info_builder.raw
    end

    def signature_value
      signed_info_builder.signed
    end

    def certificate_formatter(pem_certificate)
      pem_certificate
      .gsub(/-----BEGIN CERTIFICATE-----/,"")
      .gsub(/-----END CERTIFICATE-----/,"")
      .gsub(/\n/, "")
    end
  end
end
