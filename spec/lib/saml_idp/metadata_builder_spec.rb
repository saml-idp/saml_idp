require 'spec_helper'
module SamlIdp
  describe MetadataBuilder do
    it "has a valid fresh" do
      expect(subject.fresh).to_not be_empty
    end

    it "signs valid xml" do
      expect(Saml::XML::Document.parse(subject.signed).valid_signature?(Default::FINGERPRINT)).to be_truthy
    end

    it "includes logout element" do
      subject.configurator.single_logout_service_post_location = 'https://example.com/saml/logout'
      expect(subject.fresh).to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/saml/logout"/>')
    end

    context "technical contact" do
      before do
        subject.configurator.technical_contact.company       = nil
        subject.configurator.technical_contact.given_name    = nil
        subject.configurator.technical_contact.sur_name      = nil
        subject.configurator.technical_contact.telephone     = nil
        subject.configurator.technical_contact.email_address = nil
      end

      it "all fields" do
        subject.configurator.technical_contact.company       = "ACME Corporation"
        subject.configurator.technical_contact.given_name    = "Road"
        subject.configurator.technical_contact.sur_name      = "Runner"
        subject.configurator.technical_contact.telephone     = "1-800-555-5555"
        subject.configurator.technical_contact.email_address = "acme@example.com"

        expect(subject.fresh).to match('<ContactPerson contactType="technical"><Company>ACME Corporation</Company><GivenName>Road</GivenName><SurName>Runner</SurName><EmailAddress>mailto:acme@example.com</EmailAddress><TelephoneNumber>1-800-555-5555</TelephoneNumber></ContactPerson>')
      end

      it "no fields" do
        expect(subject.fresh).to match('<ContactPerson contactType="technical"></ContactPerson>')
      end

      it "just email" do
        subject.configurator.technical_contact.email_address = "acme@example.com"
        expect(subject.fresh).to match('<ContactPerson contactType="technical"><EmailAddress>mailto:acme@example.com</EmailAddress></ContactPerson>')
      end

    end

    it "includes logout element as HTTP Redirect" do
      subject.configurator.single_logout_service_redirect_location = 'https://example.com/saml/logout'
      expect(subject.fresh).to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/saml/logout"/>')
    end

    context '#x509_certificate' do
      context 'when the service provider has new certificate' do
        it 'extract new certificate' do
          allow_any_instance_of(ServiceProvider).to(
            receive(:new_cert?).and_return true
          )
          expect(subject.x509_certificate.length < 15).to(
            eq(Default::NEW_X509_CERTIFICATE.length < 15)
          )
        end
      end

      context 'when the service provider does not have a new certificate' do
        it 'extract default certificate' do
          subject.configurator.single_service_post_location = nil
          expect(subject.x509_certificate.length < 15).to(
            eq(Default::X509_CERTIFICATE.length < 15)
          )
        end
      end
    end
  end
end
