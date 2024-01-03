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

  metadata_with_slo = <<-eos
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     validUntil="2022-07-18T04:35:53Z"
                     cacheDuration="PT604800S"
                     entityID="http://sp.example.com/saml">
    <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="https://test/logout" />
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="http://sp.example.com/saml/acs"
                                     index="1" />
        
    </md:SPSSODescriptor>
</md:EntityDescriptor>
  eos

  describe IncomingMetadata do
    it 'should properly set sign_assertions to false' do
      metadata = SamlIdp::IncomingMetadata.new(metadata_1)
      expect(metadata.sign_assertions).to eq(false)
      expect(metadata.sign_authn_request).to eq(false)
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

    it 'should parse single logout url as array' do
      metadata = SamlIdp::IncomingMetadata.new(metadata_with_slo)
      expect(metadata.single_logout_services).to be_a(Array)
      expect(metadata.single_logout_services.size).to eq(1)
      expect(metadata.single_logout_services).to include(
        hash_including(binding: "HTTP-Redirect"),
        hash_including(location: "https://test/logout"),
        hash_including(default: false)
      )
    end
  end
end
