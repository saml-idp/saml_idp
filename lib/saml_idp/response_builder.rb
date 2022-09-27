require 'builder'
require 'saml_idp/algorithmable'
require 'saml_idp/signable'
module SamlIdp
  class ResponseBuilder
    include Algorithmable
    include Signable
    attr_accessor :response_id
    attr_accessor :issuer_uri
    attr_accessor :saml_acs_url
    attr_accessor :saml_request_id
    attr_accessor :assertion_and_signature
    attr_accessor :raw_algorithm
    attr_accessor :x509_certificate
    attr_accessor :secret_key
    attr_accessor :password

    alias_method :reference_id, :response_id

    def initialize(
      response_id,
      issuer_uri,
      saml_acs_url,
      saml_request_id,
      assertion_and_signature,
      raw_algorithm,
      x509_certificate = nil,
      secret_key = nil,
      password = nil
    )
      self.response_id = response_id
      self.issuer_uri = issuer_uri
      self.saml_acs_url = saml_acs_url
      self.saml_request_id = saml_request_id
      self.assertion_and_signature = assertion_and_signature
      self.raw_algorithm = raw_algorithm
      self.x509_certificate = x509_certificate
      self.secret_key = secret_key
      self.password = password
    end

    def encoded(signed_message: false, compress: false)
      @encoded ||= signed_message ? encode_signed_message(compress) : encode_raw_message(compress)
    end

    def raw
      build
    end

    def encode_raw_message(compress)
      Base64.strict_encode64(compress ? deflate(raw) : raw)
    end
    private :encode_raw_message

    def encode_signed_message(compress)
      Base64.strict_encode64(compress ? deflate(signed) : signed)
    end
    private :encode_signed_message

    def build
      resp_options = {}
      resp_options[:ID] = response_id_string
      resp_options[:Version] =  "2.0"
      resp_options[:IssueInstant] = now_iso
      resp_options[:Destination] = saml_acs_url
      resp_options[:Consent] = Saml::XML::Namespaces::Consents::UNSPECIFIED
      resp_options[:InResponseTo] = saml_request_id unless saml_request_id.nil?
      resp_options["xmlns:samlp"] = Saml::XML::Namespaces::PROTOCOL

      builder = Builder::XmlMarkup.new
      builder.tag! "samlp:Response", resp_options do |response|
          response.Issuer issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          sign response
          response.tag! "samlp:Status" do |status|
            status.tag! "samlp:StatusCode", Value: Saml::XML::Namespaces::Statuses::SUCCESS
          end
          response << assertion_and_signature
        end
    end
    private :build

    def response_id_string
      "_#{response_id}"
    end
    alias_method :reference_id, :response_id
    private :response_id_string

    def now_iso
      Time.now.utc.iso8601
    end
    private :now_iso

    def deflate(inflated)
      Zlib::Deflate.deflate(inflated, 9)[2..-5]
    end
    private :deflate
  end
end
