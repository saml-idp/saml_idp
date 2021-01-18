require 'spec_helper'

module SamlIdp
  describe Fingerprint do
    describe "certificate_digest" do
      let(:cert) { sp_x509_cert }
      let(:fingerprint) { "a2:cb:f6:6b:bc:2a:33:b9:4f:f3:c3:7e:26:a4:21:cd:41:83:ef:26:88:fa:ba:71:37:40:07:3e:d5:76:04:b7" }

      it "returns the fingerprint string" do
        expect(Fingerprint.certificate_digest(cert, :sha256)).to eq(fingerprint)
      end
    end
  end
end
