require 'spec_helper'

require 'saml_idp/encryptor'

module SamlIdp
  describe Encryptor do
    let(:encryption_opts) do
      {
        cert: Default::X509_CERTIFICATE,
        block_encryption: 'aes256-cbc',
        key_transport: 'rsa-oaep-mgf1p',
      }
    end

    subject { described_class.new encryption_opts }

    SamlIdp::Encryptor::ENCRYPTION_ALGORITHMS_NS.keys.each do |encryption_algorithm|
      it "encrypts XML with #{encryption_algorithm}" do
        encryption_opts[:block_encryption] = encryption_algorithm
        raw_xml = '<foo>bar</foo>'
        encrypted_xml = subject.encrypt(raw_xml)
        expect(encrypted_xml).not_to match 'bar'
        encrypted_doc = Nokogiri::XML::Document.parse(encrypted_xml)
        encrypted_data = Xmlenc::EncryptedData.new(encrypted_doc.at_xpath('//xenc:EncryptedData',
                                                                          Xmlenc::NAMESPACES))
        decrypted_xml = encrypted_data.decrypt(subject.encryption_key)
        expect(decrypted_xml).to eq(raw_xml)
      end
    end

    it 'does not have a KeyName element' do
      raw_xml = '<foo>bar</foo>'
      encrypted_xml = subject.encrypt(raw_xml)
      encrypted_doc = Nokogiri::XML::Document.parse(encrypted_xml)

      expect(encrypted_doc.remove_namespaces!.xpath('//KeyName')).to be_empty
    end

    context 'invalid block_encryption' do
      it 'raises an exception' do
        encryption_opts[:block_encryption] = 'abc123'

        expect do
          subject.encrypt('<foo>bar</foo>')
        end.to raise_error(Xmlenc::UnsupportedError)
      end
    end
  end
end
