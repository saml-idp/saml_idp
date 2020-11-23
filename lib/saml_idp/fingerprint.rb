module SamlIdp
  module Fingerprint
    def self.certificate_digest(cert, sha_size = nil)
      sha_size ||= SamlIdp.config.algorithm
      digest_sha_class(sha_size).hexdigest(OpenSSL::X509::Certificate.new(cert).to_der).scan(/../).join(':')
    end

    def self.digest_sha_class(sha_size)
      case sha_size
      when :sha256
        Digest::SHA256
      when :sha512
        Digest::SHA512
      else
        raise ArgumentError, "Unsupported sha size parameter: #{sha_size}"
      end
    end
  end
end
