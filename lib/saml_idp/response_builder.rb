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
    attr_accessor :public_cert
    attr_accessor :private_key
    attr_accessor :pv_key_password

    alias_method :reference_id, :response_id

    def initialize(
        response_id:,
        issuer_uri:,
        saml_acs_url:,
        saml_request_id:,
        assertion_and_signature:,
        raw_algorithm:,
        public_cert:,
        private_key:,
        pv_key_password:
    )
      self.response_id = response_id
      self.issuer_uri = issuer_uri
      self.saml_acs_url = saml_acs_url
      self.saml_request_id = saml_request_id
      self.assertion_and_signature = assertion_and_signature
      self.raw_algorithm = raw_algorithm
      self.public_cert = public_cert
      self.private_key = private_key
      self.pv_key_password = pv_key_password
    end

    def encoded(signed_message: false, compress: false)
      @encoded ||= signed_message ? encode_signed_message(compress) : encode_raw_message(compress)
    end

    def raw
      build
    end

    private

    def encode_raw_message(compress)
      Base64.strict_encode64(compress ? deflate(raw) : raw)
    end

    def encode_signed_message(compress)
      Base64.strict_encode64(compress ? deflate(signed) : signed)
    end

    def build
      resp_options = {}
      resp_options[:ID] = response_id_string
      resp_options[:Version] =  "2.0"
      resp_options[:IssueInstant] = now_iso
      resp_options[:Destination] = saml_acs_url
      resp_options[:Consent] = SamlIdp::XML::Namespaces::Consents::UNSPECIFIED
      resp_options[:InResponseTo] = saml_request_id unless saml_request_id.nil?
      resp_options["xmlns:samlp"] = SamlIdp::XML::Namespaces::PROTOCOL

      builder = Builder::XmlMarkup.new
      builder.tag! "samlp:Response", resp_options do |response|
          response.Issuer issuer_uri, xmlns: SamlIdp::XML::Namespaces::ASSERTION
          sign response
          response.tag! "samlp:Status" do |status|
            status.tag! "samlp:StatusCode", Value: SamlIdp::XML::Namespaces::Statuses::SUCCESS
          end
          response << assertion_and_signature
        end
    end

    def response_id_string
      "_#{response_id}"
    end

    def now_iso
      Time.now.utc.iso8601
    end

    def deflate(inflated)
      Zlib::Deflate.deflate(inflated, 9)[2..-5]
    end
  end
end
