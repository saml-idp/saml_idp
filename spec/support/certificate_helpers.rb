require 'openssl'

module CertificateHelpers
  def custom_idp_x509_cert
    File.read('spec/support/certificates/custom_idp_cert.crt')
  end

  def custom_idp_secret_key
    File.read('spec/support/certificates/custom_idp_private_key.pem')
  end

  def custom_idp_x509_cert_fingerprint
    cert = OpenSSL::X509::Certificate.new(custom_idp_x509_cert)
    digest = OpenSSL::Digest::SHA1.new(cert.to_der)
    digest.hexdigest.upcase.scan(/.{2}/).join(':')
  end

  def encrypted_secret_key
    key = OpenSSL::PKey::RSA.new(SamlIdp::Default::SECRET_KEY)
    key.to_pem(OpenSSL::Cipher.new('aes-128-cbc'), encrypted_secret_key_password)
  end

  def encrypted_secret_key_password
    'im a secret password.'
  end

  def invalid_cert
    OpenSSL::X509::Certificate.new(File.read('spec/support/certificates/too_short_cert.crt'))
  end

  def add_cert_boundaries(cert_text)
    <<~TEXT
      -----BEGIN CERTIFICATE-----
      #{cert_text}
      -----END CERTIFICATE-----
    TEXT
  end

  def remove_cert_boundaries(cert)
    cert.
      gsub("-----BEGIN CERTIFICATE-----\n", '').
      gsub("\n-----END CERTIFICATE-----\n", '')
  end
end
