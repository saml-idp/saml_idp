require 'spec_helper'
module SamlIdp
  describe MetadataBuilder do
    it "has a valid fresh" do
      expect(subject.fresh).to_not be_empty
    end

    it "signs valid xml" do
      expect(Saml::XML::Document.parse(subject.signed).valid_signature?("", Default::FINGERPRINT)).to be_truthy
    end

    it "includes logout element" do
      subject.configurator.single_logout_service_post_location = 'https://example.com/saml/logout'
      subject.configurator.single_logout_service_redirect_location = 'https://example.com/saml/logout'
      expect(subject.fresh).to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/saml/logout"/>')
      expect(subject.fresh).to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/saml/logout"/>')
    end

    it 'will not includes empty logout endpoint' do
      subject.configurator.single_logout_service_post_location = ''
      subject.configurator.single_logout_service_redirect_location = nil
      expect(subject.fresh).not_to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"')
      expect(subject.fresh).not_to match('<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"')
    end

    it 'will includes sso element' do
      subject.configurator.single_service_post_location = 'https://example.com/saml/sso'
      subject.configurator.single_service_redirect_location = 'https://example.com/saml/sso'
      expect(subject.fresh).to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/saml/sso"/>')
      expect(subject.fresh).to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/saml/sso"/>')
    end

    it 'will not includes empty sso element' do
      subject.configurator.single_service_post_location = ''
      subject.configurator.single_service_redirect_location = nil
      expect(subject.fresh).not_to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"')
      expect(subject.fresh).not_to match('<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"')
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

    context 'with custom configurator' do
      let(:certificate) {'a certificate'}
      let(:configurator) do SamlIdp::Configurator.new.tap do |c|
        c.secret_key = 'a private key'
        c.x509_certificate = certificate
        end
      end
      subject { described_class.new(configurator) }

      describe '.private_key' do
        it 'returns the given private_key' do
          expect(subject.private_key).to eq(configurator.secret_key)
        end
      end

      describe '.x509_certificate' do
        context 'with a given certificate string' do
          it 'returns the given certificate' do
            expect(subject.x509_certificate).to eq('a certificate')
          end
        end

        context 'with a given certificate proc' do
          let(:certificate) {Proc.new { "a certificate from proc"}}
          it 'returns the given certificate' do
            expect(subject.x509_certificate).to eq('a certificate from proc')
          end
        end
      end
    end
  end
end
