require 'builder'
module SamlIdp
  class LogoutBuilder
    include Signable

    attr_accessor :response_id
    attr_accessor :issuer_uri
    attr_accessor :saml_slo_url
    attr_accessor :algorithm
    attr_accessor :x509_certificate
    attr_accessor :secret_key
    attr_accessor :password

    def initialize(
      response_id,
      issuer_uri,
      saml_slo_url,
      algorithm,
      x509_certificate = nil,
      secret_key = nil,
      password = nil
    )
      self.response_id = response_id
      self.issuer_uri = issuer_uri
      self.saml_slo_url = saml_slo_url
      self.algorithm = algorithm
      self.x509_certificate = x509_certificate
      self.secret_key = secret_key
      self.password = password
    end

    # this is an abstract base class.
    def build
      raise "#{self.class} must implement build method"
    end

    def reference_id
      self.response_id
    end

    def encoded
      @encoded ||= encode
    end

    def raw
      build
    end

    def encode
      Base64.strict_encode64(raw)
    end
    private :encode

    def response_id_string
      "_#{response_id}"
    end
    private :response_id_string

    def now_iso
      Time.now.utc.iso8601
    end
    private :now_iso
  end
end
