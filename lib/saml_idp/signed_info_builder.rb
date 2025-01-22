require 'builder'
module SamlIdp
  class SignedInfoBuilder
    include Algorithmable

    SIGNATURE_METHODS = {
      "sha1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
      "sha224" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
      "sha256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      "sha384" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
      "sha512" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    }
    DIGEST_METHODS = {
      "sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
      "sha224" => "http://www.w3.org/2001/04/xmldsig-more#sha224",
      "sha256" => "http://www.w3.org/2001/04/xmlenc#sha256",
      "sha384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
      "sha512" => "http://www.w3.org/2001/04/xmlenc#sha512",
    }


    attr_accessor :reference_id
    attr_accessor :digest_value
    attr_accessor :raw_algorithm
    attr_accessor :private_key
    attr_accessor :pv_key_password

    def initialize(reference_id, digest_value, raw_algorithm, private_key, pv_key_password)
      self.reference_id = reference_id
      self.digest_value = digest_value
      self.raw_algorithm = raw_algorithm
      self.private_key = private_key
      self.pv_key_password = pv_key_password
    end

    def raw
      builder = Builder::XmlMarkup.new
      builder.tag! "ds:SignedInfo", "xmlns:ds" => "http://www.w3.org/2000/09/xmldsig#" do |signed_info|
        signed_info.tag!("ds:CanonicalizationMethod", Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#") {}
        signed_info.tag!("ds:SignatureMethod", Algorithm: signature_method ) {}
        signed_info.tag! "ds:Reference", URI: reference_string do |reference|
          reference.tag! "ds:Transforms" do |transforms|
            transforms.tag!("ds:Transform", Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature") {}
            transforms.tag!("ds:Transform", Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#") {}
          end
          reference.tag!("ds:DigestMethod", Algorithm: digest_method) {}
          reference.tag! "ds:DigestValue", digest_value
        end
      end
    end

    def signed
      encoded.gsub(/\n/, "")
    end

    private

    def digest_method
      DIGEST_METHODS.fetch(clean_algorithm_name, DIGEST_METHODS["sha1"])
    end

    def signature_method
      SIGNATURE_METHODS.fetch(clean_algorithm_name, SIGNATURE_METHODS["sha1"])
    end

    def clean_algorithm_name
      algorithm_name.to_s.downcase
    end

    def encoded
      key = OpenSSL::PKey::RSA.new(private_key, pv_key_password)
      Base64.strict_encode64(key.sign(algorithm.new, raw))
    end

    def reference_string
      "#_#{reference_id}"
    end
  end
end
