require 'spec_helper'
module SamlIdp

  metadata_1 = <<-eos
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test" entityID="https://test-saml.com/saml">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="false">
  </md:SPSSODescriptor>
</md:EntityDescriptor>
  eos

  metadata_2 = <<-eos
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test" entityID="https://test-saml.com/saml">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
  </md:SPSSODescriptor>
</md:EntityDescriptor>
  eos

  metadata_3 = <<-eos
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test" entityID="https://test-saml.com/saml">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true">
  </md:SPSSODescriptor>
</md:EntityDescriptor>
  eos

  metadata_4 = <<-eos
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test" entityID="https://test-saml.com/saml">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  </md:SPSSODescriptor>
</md:EntityDescriptor>
  eos

  describe IncomingMetadata do
    it 'should properly set sign_assertions to false' do
      metadata = SamlIdp::IncomingMetadata.new(metadata_1)
      expect(metadata.sign_assertions).to eq(false)
    end

    it 'should properly set entity_id as https://test-saml.com/saml' do
      metadata = SamlIdp::IncomingMetadata.new(metadata_1)
      expect(metadata.entity_id).to eq('https://test-saml.com/saml')
    end

    it 'should properly set sign_assertions to true' do
      metadata = SamlIdp::IncomingMetadata.new(metadata_2)
      expect(metadata.sign_assertions).to eq(true)
      expect(metadata.sign_authn_request).to eq(true)
    end

    it 'should properly set sign_assertions to false when WantAssertionsSigned is not included' do
      metadata = SamlIdp::IncomingMetadata.new(metadata_3)
      expect(metadata.sign_assertions).to eq(false)
    end

    it 'should properly set sign_authn_request to false when AuthnRequestsSigned is not included' do
      metadata = SamlIdp::IncomingMetadata.new(metadata_4)
      expect(metadata.sign_authn_request).to eq(false)
    end
  end
end
