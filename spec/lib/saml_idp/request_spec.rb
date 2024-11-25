require 'spec_helper'
module SamlIdp
  describe Request do
    let(:ial) { 'http://idmanagement.gov/ns/assurance/ial/2' }
    let(:vtr) { 'C1.C2.P1.Pb' }
    let(:authn_context_classref) { 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' }
    let(:issuer) { 'localhost:3000' }
    let(:local_overrides) { {} }
    let(:security_overrides) { {} }
    let(:signed) { false }

    let(:encoded_request) do
      custom_saml_request(
        overrides: { issuer:, authn_context: authn_context_classref }.
          merge(local_overrides),
        security_overrides:,
        signed:
      )
    end

    subject { described_class.from_deflated_request(encoded_request) }

    describe 'deflated request' do
      let(:issuer) { 'a specific issuer' }
      let(:local_overrides) { { issuer: } }

      it 'inflates' do
        expect(subject.issuer).to eq(issuer)
      end

      context 'when SAML is invalid' do
        subject { described_class.from_deflated_request 'not saml' }

        it 'does not blow up' do
          expect(subject.valid?).to be false
        end
      end
    end

    describe 'authn request' do
      it 'has a valid request_id' do
        expect(subject.request_id).to be_a String
      end

      it 'has a valid acs_url' do
        expect(subject.acs_url).to eq saml_settings.assertion_consumer_service_url
      end

      it 'has a valid service_provider' do
        expect(subject.service_provider).to be_a ServiceProvider
      end

      it 'has a valid issuer' do
        expect(subject.issuer).to eq(issuer)
      end

      it 'has a valid valid_signature' do
        expect(subject.valid_signature?).to be true
      end

      it "correctly indicates that it isn't signed" do
        expect(subject.signed?).to be false
      end

      context 'with a signed request' do
        let(:signed) { true }

        it 'has a valid valid_signature' do
          expect(subject.valid_signature?).to be true
        end

        it "correctly indicates that it isn't signed" do
          expect(subject.signed?).to be true
        end
      end

      context 'the request has no namespace' do
        subject { described_class.new fixture('valid_no_ns.xml', path: 'requests') }

        it 'has a valid valid_signature' do
          expect(subject.valid_signature?).to be true
        end

        it "correctly indicates that it is signed" do
          expect(subject.signed?).to be true
        end
      end

      context 'the request has an unknown namespace' do
        subject { described_class.new fixture('valid_unknown_ns_authn.xml', path: 'requests') }

        it 'has a valid valid_signature' do
          expect(subject.valid_signature?).to be true
        end

        it "correctly indicates that it isn't signed" do
          expect(subject.signed?).to be false
        end
      end

      context 'with signature in params' do
        subject do
          described_class.from_deflated_request(
            encoded_request,
            get_params: { Signature: 'abc' }
          )
        end

        it 'correctly indicates that it is signed (even invalidly)' do
          expect(subject.signed?).to be_truthy
        end
      end

      context 'with an enveloped signature' do
        let(:signed) { true }

        it 'correctly indicates that it is signed (even invalidly)' do
          expect(subject.signed?).to be true
        end
      end

      it 'returns acs_url for response_url' do
        expect(subject.response_url).to eq(subject.acs_url)
      end

      it 'is a authn request' do
        expect(subject.authn_request?).to eq(true)
      end

      it 'fetches internal request' do
        expect(subject.request['ID']).to eq(subject.request_id)
      end

      it 'has a valid name id format' do
        expect(subject.name_id_format).to eq('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
      end

      it 'has a valid requested authn context comparison' do
        expect(subject.requested_authn_context_comparison).to eq('exact')
      end

      context 'empty issuer' do
        let(:issuer) { nil }

        it 'does not permit empty issuer' do
          expect(subject.issuer).not_to eq('')
          expect(subject.issuer).to eq(nil)
        end
      end

      it 'defaults to force_authn = false' do
        expect(subject.force_authn?).to be_falsey
      end

      describe 'ForceAuthn values' do
        let(:force_authn) { true }
        let(:local_overrides) { { force_authn: } }

        it 'properly parses ForceAuthn="true" if passed' do
          expect(subject.force_authn?).to be true
        end

        context 'when force_authn is false' do
          let(:force_authn) { false }

          it 'properly parses ForceAuthn="false" if passed' do
            expect(subject.force_authn?).to be_falsey
          end
        end
      end


      describe 'unspecified name id format' do
        let(:local_overrides) { { name_identifier_format: nil } }

        it 'returns nil for name id format' do
          expect(subject.name_id_format).to eq(nil)
        end
      end
    end

    describe 'logout request' do
      let(:encoded_request) { custom_logout_request(overrides: { issuer: }) }

      subject do
        described_class.from_deflated_request(
          encoded_request["SAMLRequest"],
          get_params: encoded_request
        )
      end

      it 'has a valid request_id' do
        expect(subject.request_id).to be_a String
      end

      it 'is flagged as a logout_request' do
        expect(subject.logout_request?).to eq(true)
      end

      it 'has a valid name_id' do
        expect(subject.name_id).to eq('some-user-id')
      end

      it 'has a valid issuer' do
        expect(subject.issuer).to eq(issuer)
      end

      it 'fetches internal request' do
        expect(subject.request['ID']).to eq(subject.request_id)
      end

      it 'returns logout_url for response_url' do
        expect(subject.response_url).to eq(subject.logout_url)
      end
    end

    describe '#requested_vtr_authn_contexts' do
      subject { described_class.from_deflated_request encoded_request }

      context 'no vtr context requested' do
        let(:authn_context_classref) { '' }

        it 'returns an empty array' do
          expect(subject.requested_vtr_authn_contexts).to eq([])
        end
      end

      context 'only vtr is requested' do
        let(:authn_context_classref) { vtr }

        it 'returns the vrt' do
          expect(subject.requested_vtr_authn_contexts).to eq([vtr])
        end
      end

      context 'multiple contexts including vtr and an old ACR context' do
        let(:authn_context_classref) { [vtr, ial] }

        it 'returns the vrt' do
          expect(subject.requested_vtr_authn_contexts).to eq([vtr])
        end
      end

      context 'multiple contexts that are vectors of trust' do
        let(:authn_context_classref) { [vtr, 'C1.C2.P1'] }

        it 'returns all of the vectors in an array' do
          expect(subject.requested_vtr_authn_contexts).to eq([vtr, 'C1.C2.P1'])
        end
      end

      context 'context that contains a VTR substring but is not a VTR' do
        let(:authn_context_classref) do
          'Not a VTR but does contain LetT3.Rs and Nu.Mb.Ers'
        end

        it 'does not match on the context' do
          expect(subject.requested_vtr_authn_contexts).to eq([])
        end
      end

      context 'with the default MFA context' do
        let(:authn_context_classref) { 'urn:gov:gsa:ac:classes:sp:PasswordProtectedTransport:duo' }

        it 'does not match on the context' do
          expect(subject.requested_vtr_authn_contexts).to eq([])
        end
      end
    end

    describe '#valid?' do
      context 'a valid request' do
        it 'returns true' do
          expect(subject.valid?).to be true
        end

        it 'has no errors' do
          expect(subject.errors.blank?).to be true
        end
      end

      context 'an invalid request' do
        describe 'a request with no issuer' do
          let(:issuer) { nil }

          it 'is not valid' do
            expect(subject.valid?).to eq(false)
          end

          it 'adds an error to the request object' do
            subject.valid?

            expect(subject.errors.first).to eq :issuer_missing_or_invald
          end
        end

        describe 'no authn_request OR logout_request tag' do
          let(:request_saml) do
            "<saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>localhost:3000</saml:Issuer><samlp:RequestedAuthnContext Comparison='exact'></samlp:RequestedAuthnContext>"
          end
          subject { described_class.new request_saml }

          it 'is not valid' do
            expect(subject.valid?).to eq false
          end

          it 'adds an error to request object' do
            subject.valid?

            expect(subject.errors.first).to eq :no_auth_or_logout_request
          end
        end

        describe 'both an authn_request AND logout_request tag' do
          let(:auth_request) do
            "<samlp:AuthnRequest IssueInstant='2013-08-06T22:01:35Z' Version='2.0' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{issuer}</saml:Issuer>"
          end

          let(:logout_request) do
            "<samlp:LogoutRequest Destination='http://localhost:3000/saml/logout' xmlns='urn:oasis:names:tc:SAML:2.0:protocol'><Issuer xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>http://example.com</Issuer></samlp:LogoutRequest>"
          end

          subject { described_class.new auth_request + logout_request + "</samlp:AuthnRequest>"}

          it 'is not valid' do
            expect(subject.valid?).to eq false
          end

          it 'adds an error to request object' do
            subject.valid?
            expect(subject.errors.first).to eq :both_auth_and_logout_request
          end
        end

        describe 'there is no response url' do
          describe 'authn_request' do
            let(:local_overrides) { { assertion_consumer_service_url: nil } }

            it 'is not valid' do
              expect(subject.valid?).to eq false
            end

            it 'adds an error to request object' do
              subject.valid?
              expect(subject.errors.first).to eq :no_response_url
            end
          end

          describe 'logout_request' do
            let(:encoded_request) { custom_logout_request }

            subject do
              described_class.from_deflated_request(
                encoded_request["SAMLRequest"],
                get_params: encoded_request
              )
            end

            before do
              subject.service_provider.assertion_consumer_logout_service_url = nil
            end

            it 'is not valid' do
              expect(subject.valid?).to eq false
            end

            it 'adds an error to request object' do
              subject.valid?
              expect(subject.errors.first).to eq :no_response_url
            end
          end
        end

        describe 'invalid signature' do
          let(:encoded_request) { custom_logout_request }

          subject do
            described_class.from_deflated_request(
              encoded_request["SAMLRequest"],
              get_params: encoded_request
            )
          end

          before do
            subject.service_provider.assertion_consumer_logout_service_url = ' https://example.com/logout'
            subject.service_provider.certs = []
          end

          it 'is not valid' do
            expect(subject.valid?).to eq false
          end

          it 'adds an error to request object' do
            # service_provider has no certificates embedded, so signature is invalid
            subject.valid?
            expect(subject.errors.include?(:invalid_signature)).to be true
          end
        end
      end
    end

    describe '#matching_cert' do
      context 'when document is not signed' do
        it 'returns nil' do
          expect(subject.matching_cert).to be_nil
        end
      end

      context 'when document is signed' do
        let(:signed) { true }
        let(:service_provider) { subject.service_provider }
        let(:cert) { saml_settings.get_sp_cert }

        describe 'the service provider has no registered certs' do
          before { subject.service_provider.certs = [] }

          it 'returns nil' do
            expect(subject.matching_cert).to be_nil
          end
        end

        describe 'the service provider has one registered cert' do
          before { subject.service_provider.certs = [cert] }

          describe 'the cert matches the assertion cert' do
            it 'returns the cert' do
              expect(subject.matching_cert).to eq cert
            end
          end

          describe 'the cert does not match the assertion cert' do
            let(:cert) { OpenSSL::X509::Certificate.new(custom_idp_x509_cert) }

            it 'returns nil' do
              expect(subject.matching_cert).to be_nil
            end
          end
        end

        describe 'multiple certs' do
          let(:not_matching_cert) { OpenSSL::X509::Certificate.new(custom_idp_x509_cert) }

          before { subject.service_provider.certs = [not_matching_cert, invalid_cert, cert] }

          it 'returns the matching cert' do
            expect(subject.matching_cert).to eq cert
          end
        end
      end
    end

    describe '#sha256_validation_matching_cert' do
      context 'when document is not signed' do
        it 'returns nil' do
          expect(subject.matching_cert).to be_nil
        end
      end

      context 'when document is signed' do
        let(:signed) { true }
        let(:service_provider) { subject.service_provider }
        let(:cert) { saml_settings.get_sp_cert }

        describe 'the service provider has no registered certs' do
          before { subject.service_provider.certs = [] }

          it 'returns nil' do
            expect(subject.sha256_validation_matching_cert).to be_nil
          end
        end

        describe 'the service provider has one registered cert' do
          before { subject.service_provider.certs = [cert] }

          describe 'the cert matches the assertion cert' do
            it 'returns the cert' do
              expect(subject.sha256_validation_matching_cert).to eq cert
            end

            context 'when the signature algorithm is not right' do
              let(:security_overrides) do
                {
                  signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1"
                }
              end

              it 'returns nil' do
                expect(subject.sha256_validation_matching_cert).to eq nil
              end
            end
          end

          describe 'the cert does not match the assertion cert' do
            let(:cert) { OpenSSL::X509::Certificate.new(custom_idp_x509_cert) }

            it 'returns nil' do
              expect(subject.sha256_validation_matching_cert).to be_nil
            end
          end
        end

        describe 'multiple certs' do
          let(:not_matching_cert) { OpenSSL::X509::Certificate.new(custom_idp_x509_cert) }

          before { subject.service_provider.certs = [not_matching_cert, invalid_cert, cert] }

          it 'returns the matching cert' do
            expect(subject.sha256_validation_matching_cert).to eq cert
          end

          context 'when the signature algorithm is not right' do
            let(:security_overrides) do
              {
                signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1"
              }
            end

            it 'returns nil' do
              expect(subject.sha256_validation_matching_cert).to eq nil
            end
          end
        end
      end
    end

    describe '#cert_errors' do
      describe 'document is not signed' do
        let(:signed) { false }

        it 'returns nil' do
          expect(subject.cert_errors).to be_nil
        end
      end

      describe 'document is signed' do
        let(:signed) { true }
        let(:service_provider) { subject.service_provider }
        let(:cert) { saml_settings.get_sp_cert }

        describe 'the service provider has no registered certs' do
          before { subject.service_provider.certs = [] }

          it 'returns a no registered cert error' do
            expect(subject.cert_errors).to eq [{cert: nil, error_code: :no_registered_certs}]
          end
        end

        describe 'the service provider has one registered cert' do
          before { subject.service_provider.certs = [cert] }
          let(:errors) { [{ cert: cert.serial.to_s, error_code: error_code }] }

          describe 'the cert matches the assertion cert' do
            it 'returns nil' do
              expect(subject.cert_errors).to be_nil
            end
          end

          describe 'the embedded certificate is bad' do
            let(:signed) { true }
            let(:local_overrides) { { certificate: invalid_cert.to_pem } }
            let(:error_code) { :invalid_certificate_in_request }

            before do
              allow(OpenSSL::X509::Certificate).to receive(:new).and_raise OpenSSL::X509::CertificateError
            end

            it 'returns an invalid certificate error' do
              expect(subject.cert_errors).to eq errors
            end
          end

          describe 'the cert element exists but is empty' do
            let(:error_code) { :no_certificate_in_request }
            let(:errors) { [{ cert: nil, error_code: error_code }] }
            let(:blank_cert_element_req) do
              <<-XML.gsub(/^[\s]+|[\s]+\n/, '')
                <?xml version="1.0"?>
                <samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://www.example.com/api/saml/logout2024" ID="_223d186c-35a0-4d1f-b81a-c473ad496415" IssueInstant="2024-01-11T18:22:03Z" Version="2.0">
                  <saml:Issuer>http://localhost:3000</saml:Issuer>
                  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:SignedInfo>
                      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                      <ds:Reference URI="#_223d186c-35a0-4d1f-b81a-c473ad496415">
                        <ds:Transforms>
                          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                            <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="#default samlp saml ds xs xsi md"/>
                          </ds:Transform>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>2Nb3RLbiFHn0cyn+7JA7hWbbK1NvFMVGa4MYTb3Q91I=</ds:DigestValue>
                      </ds:Reference>
                    </ds:SignedInfo>
                    <ds:SignatureValue>UmsRcaWkHXrUnBMfOQBC2DIQk1rkQqMc5oucz6FAjulq0ZX7qT+zUbSZ7K/us+lzcL1hrgHXi2wxjKSRiisWrJNSmbIGGZIa4+U8wIMhkuY5vZVKgxRc2aP88i/lWwURMI183ifAzCwpq5Y4yaJ6pH+jbgYOtmOhcXh1OwrI+QqR7QSglyUJ55WO+BCR07Hf8A7DSA/Wgp9xH+DUw1EnwbDdzoi7TFqaHY8S4SWIcc26DHsq88mjsmsxAFRQ+4t6nadOnrrFnJWKJeiFlD8MxcQuBiuYBetKRLIPxyXKFxjEn7EkJ5zDkkrBWyUT4VT/JnthUlD825D+v81ZXIX3Tg==</ds:SignatureValue>
                    <ds:KeyInfo>
                      <ds:X509Data>
                        <ds:X509Certificate>
                        </ds:X509Certificate>
                      </ds:X509Data>
                    </ds:KeyInfo>
                  </ds:Signature>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_13ae90d1-2f9b-4ed5-b84d-3722ea42e386</saml:NameID>
                </samlp:LogoutRequest>
              XML
            end
            let(:saml_request) do
              Base64.encode64(Zlib::Deflate.deflate(blank_cert_element_req, 9)[2..-5])
            end

            subject { described_class.from_deflated_request saml_request }

            it 'returns a no certificate in request error' do
              expect(subject.cert_errors).to eq errors
            end
          end

          describe 'the cert does not match the assertion cert' do
            describe 'returns a fingerprint mismatch error' do
              let(:cert) { OpenSSL::X509::Certificate.new(custom_idp_x509_cert) }
              let(:error_code) { :fingerprint_mismatch }

              it 'returns nil' do
                expect(subject.cert_errors).to eq errors
              end
            end
          end
        end

        describe 'sp has multiple certs' do
          let(:not_matching_cert) { OpenSSL::X509::Certificate.new(custom_idp_x509_cert) }

          before { subject.service_provider.certs = [not_matching_cert, invalid_cert, cert] }
          describe 'there is a matching cert' do
            it 'returns nil' do
              expect(subject.cert_errors).to be_nil
            end
          end

          describe 'there are no matching certs' do
            before { subject.service_provider.certs = [not_matching_cert, invalid_cert] }

            it 'returns multiple errors' do
              expected_errors = [
                { cert: not_matching_cert.serial.to_s, error_code: :fingerprint_mismatch },
                { cert: invalid_cert.serial.to_s, error_code: :fingerprint_mismatch },
              ]
              expect(subject.cert_errors).to eq expected_errors
            end

          end
        end
      end
    end

    def build_authn_context_classref(contexts)
      [contexts].flatten.map do |c|
        "<saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{c}</saml:AuthnContextClassRef>"
      end.join
    end
  end
end
