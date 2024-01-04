class CertificateGenerator
  attr_accessor :rsa_key, :cert, :common_name,
                :private_key, :pv_key_password

  def initialize(common_name = nil)
    self.common_name = common_name
    self.pv_key_password = SecureRandom.hex(12)
    build_certificate
    self.private_key = rsa_key.to_pem(OpenSSL::Cipher.new('AES-128-CBC'), pv_key_password)
  end

  def certificate
    cert.to_pem
  end

  private

  def build_certificate
    self.rsa_key = OpenSSL::PKey::RSA.new(2048)
    self.common_name ||= 'SAMLCertificate'
    subject = "/C=MN/OU=SAMLIdP"

    self.cert = OpenSSL::X509::Certificate.new
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
    cert.not_before = Time.now
    cert.not_after = Time.now.since(10.years)
    cert.public_key = rsa_key.public_key
    cert.serial = OpenSSL::BN.rand(160)
    cert.version = 2

    cert.sign rsa_key, OpenSSL::Digest.new('SHA256')
  end
end
