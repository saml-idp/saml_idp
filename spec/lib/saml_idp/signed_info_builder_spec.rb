require 'spec_helper'
module SamlIdp
  describe SignedInfoBuilder do
    let(:reference_id) { "abc" }
    let(:digest) { "em8csGAWynywpe8S4nN64o56/4DosXi2XWMY6RJ6YfA=" }
    let(:algorithm) { :sha256 }
    let(:audience_uri) { '' }
    subject { described_class.new(
      reference_id,
      digest,
      algorithm,
      audience_uri
    ) }

    before do
      allow(Time).to receive(:now).and_return Time.parse("Jul 31 2013")
    end

    it "builds a legit raw XML file" do
      expect(subject.raw).to eq("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#_abc\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>em8csGAWynywpe8S4nN64o56/4DosXi2XWMY6RJ6YfA=</ds:DigestValue></ds:Reference></ds:SignedInfo>")
    end

    it "builds a legit digest of the XML file" do
      expect(subject.signed).to eq("hKLeWLRgatHcV6N5Fc8aKveqNp6Y/J4m2WSYp0awGFtsCTa/2nab32wI3du+3kuuIy59EDKeUhHVxEfyhoHUo6xTZuO2N7XcTpSonuZ/CB3WjozC2Q/9elss3z1rOC3154v5pW4puirLPRoG+Pwi8SmptxNRHczr6NvmfYmmGfo=")
    end

    context '#signed' do
      context 'when provider has a new certificate' do
        before do
          allow_any_instance_of(ServiceProvider).to(
            receive(:new_cert?).and_return true
          )
        end

        it 'return a different signed encoded' do
          expect(subject.signed).to eq("No41nwOoVEXgKz2iKUZuR0g5hnTArkMSN40Qk98XzbLUObgTg68k3cAU8KMyr5cfMC7rMQdtbDTgYn6vKCHI2Yf8k/cmRD9f+YHixnosepUMlQeBkeN/QL4f44vtaeKDUA4j0C0B2vhZZT4FHGi88z2PooTzQAfdhh2j/Wuutaw=")
        end
      end

      context 'when provider do not have a new certificates' do
        it 'return signed encoded' do
          expect(subject.signed).to eq("hKLeWLRgatHcV6N5Fc8aKveqNp6Y/J4m2WSYp0awGFtsCTa/2nab32wI3du+3kuuIy59EDKeUhHVxEfyhoHUo6xTZuO2N7XcTpSonuZ/CB3WjozC2Q/9elss3z1rOC3154v5pW4puirLPRoG+Pwi8SmptxNRHczr6NvmfYmmGfo=")
        end
      end
    end
  end
end
