require 'spec_helper'
require 'xml_security'

module SamlIdp
  describe 'XmlSecurity::SignedDocument' do
    let(:xml_string) { fixture('valid_SHA256.xml', path: 'requests') }
    let(:ds_namespace) { { 'ds' => 'http://www.w3.org/2000/09/xmldsig#' } }
    let(:auth_request) { custom_saml_request }
    let(:request) { Request.from_deflated_request(auth_request) }
    let(:base64_cert_text) { saml_settings.certificate }
    let(:base64_cert) { OpenSSL::X509::Certificate.new(Base64.decode64(saml_settings.certificate)) }

    subject do
      request.send(:document).signed_document
    end

    describe '#validate_doc' do
      describe 'when softly validating' do
        before do
          allow(subject).to receive(:digests_match?).and_return false
        end

        it 'does not throw NS related exceptions' do
          expect(subject.validate_doc(base64_cert_text, true)).to be_falsey
        end

        context 'with multiple validations' do
          it 'does not raise an error' do
            expect { 2.times { subject.validate_doc(base64_cert_text, true) } }.not_to raise_error
          end
        end
      end

      describe 'when throwing errors' do
        context 'when when the certs do not match' do
          let(:wrong_cert) { remove_cert_boundaries(custom_idp_x509_cert) }

          it 'raises key validation error' do
            expect { subject.validate_doc(wrong_cert, false) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Key validation error'
              )
            )
          end
        end

        context 'when the digests do not match' do
          before do
            allow(subject).to receive(:digests_match?).and_return false
          end

          it 'raises digest mismatch error' do
            expect { subject.validate_doc(base64_cert_text, false) }.to(
              raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                          'Digest mismatch')
            )
          end
        end
      end
    end

    describe '#validate' do
      context 'with an embedded request' do
        let(:cert_element) { double Nokogiri::XML::Element }

        context 'when the request certificate does not match an idp certificate' do
          let(:wrong_cert) { remove_cert_boundaries(custom_idp_x509_cert) }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return(wrong_cert)
          end

          context 'when it is failing softly' do
            it 'returns false' do
              expect(subject.validate(base64_cert)).to be false
            end
          end

          context 'when it is throwing errors' do
            it 'raises an error' do
              expect { subject.validate(base64_cert, soft: false) }.to(
                raise_error(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'Request certificate not valid or registered'
                )
              )
            end
          end
        end

        context 'when the request certificate is invalid' do
          let(:wrong_cert) { 'invalid_cert' }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return(wrong_cert)
          end

          context 'when it is failing softly' do
            it 'returns false' do
              expect(subject.validate(base64_cert)).to be false
            end
          end

          context 'when it is raising errors' do
            it 'raises an error' do
              expect { subject.validate(base64_cert, soft: false) }.to(
                raise_error(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'Request certificate not valid or registered'
                )
              )
            end
          end

          context 'when x509Certicate node exists but is blank' do
            before do
              allow(subject.document).to receive(:at_xpath).
                with('//ds:X509Certificate | //X509Certificate', ds_namespace).
                and_return(cert_element)

              allow(cert_element).to receive(:text).and_return(wrong_cert)
            end

            context 'when it is failing softly' do
              it 'returns false' do
                expect(subject.validate(base64_cert)).to be false
              end
            end

            context 'when it is raising errors' do
              it 'raises validation error' do
                expect { subject.validate(base64_cert, soft: false) }.to(
                  raise_error(
                    SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                    'Request certificate not valid or registered'
                  )
                )
              end
            end
          end
        end

        context 'with different signing algorithms' do
          let(:signature_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }
          let(:digest_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }

          let(:auth_request) do
            custom_saml_request(
              security_overrides: {
                signature_method:,
                digest_method:,
              }
            )
          end

          context 'when using SHA1 as a signing algorithm' do
            let(:algorithm) { '1' }

            context 'when failing softly' do
              it 'returns false' do
                expect(subject.validate(base64_cert)).to be false
              end
            end

            context 'when raising errors' do
              it 'raises an error' do
                expect { subject.validate(base64_cert, soft: false) }.to(
                  raise_error(
                    SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                    'Signature Algorithm needs to be SHA256'
                  )
                )
              end
            end
          end

          context 'when using SHA256 as a signing algorithm' do
            let(:algorithm) { '256' }

            it 'validate using SHA256' do
              expect(subject.validate(base64_cert)).to be true
            end
          end

          context 'when using SHA384 as a signing algorithm' do
            let(:algorithm) { '384' }

            context 'when failing softly' do
              it 'returns false' do
                expect(subject.validate(base64_cert)).to be false
              end
            end

            context 'when raising errors' do
              it 'raises an error' do
                expect { subject.validate(base64_cert, soft: false) }.to(
                  raise_error(
                    SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                    'Signature Algorithm needs to be SHA256'
                  )
                )
              end
            end
          end

          context 'when using SHA512 as a signing algorithm' do
            let(:algorithm) { '512' }

            context 'when failing softly' do
              it 'returns false' do
                expect(subject.validate(base64_cert)).to be false
              end
            end

            context 'when raising errors' do
              it 'raises an error' do
                expect { subject.validate(base64_cert, soft: false) }.to(
                  raise_error(
                    SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                    'Signature Algorithm needs to be SHA256'
                  )
                )
              end
            end
          end
        end
      end
    end

    describe '#extract_inclusive_namespaces' do
      context 'explicit namespace resolution' do
        it 'supports explicit namespace resolution for exclusive canonicalization' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to eq(%w[#default samlp saml ds xs xsi md])
        end
      end

      context 'implicit namespace resolution' do
        subject { XMLSecurity::SignedDocument.new(xml_string) }
        # using XML response to test no namespace for the InclusiveNamespaces element
        let(:xml_string) { fixture('no_signature_ns.xml') }

        it 'supports implicit namespace resolution for exclusive canonicalization' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to eq(%w[#default saml ds xs xsi])
        end
      end

      context 'inclusive namespace element is missing' do
        before do
          allow(subject.document).to receive(:at_xpath).
            with('//ec:InclusiveNamespaces', { 'ec' => 'http://www.w3.org/2001/10/xml-exc-c14n#' }).
            and_return(nil)
        end

        it 'return an empty list when inclusive namespace element is missing' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to be_empty
        end
      end
    end
  end
end
