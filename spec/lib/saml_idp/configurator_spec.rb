require 'spec_helper'
module SamlIdp
  describe Configurator do
    it { should respond_to :x509_certificate }
    it { should respond_to :secret_key }
    it { should respond_to :algorithm }
    it { should respond_to :organization_name }
    it { should respond_to :organization_url }
    it { should respond_to :base_saml_location }
    it { should respond_to :reference_id_generator }
    it { should respond_to :attribute_service_location }
    it { should respond_to :single_service_redirect_location }
    it { should respond_to :single_service_post_location }
    it { should respond_to :single_logout_service_post_location }
    it { should respond_to :single_logout_service_redirect_location }
    it { should respond_to :name_id }
    it { should respond_to :attributes }
    it { should respond_to :service_provider }
    it { should respond_to :session_expiry }
    it { should respond_to :logger }

    it "has a valid x509_certificate" do
      expect(subject.x509_certificate.call).to eq(Default::X509_CERTIFICATE)
    end

    it "has a valid secret_key" do
      expect(subject.secret_key.call).to eq(Default::SECRET_KEY)
    end

    it "has a valid algorithm" do
      expect(subject.algorithm).to eq(:sha1)
    end

    it "has a valid reference_id_generator" do
      expect(subject.reference_id_generator).to respond_to :call
    end


    it "can call service provider finder" do
      expect(subject.service_provider.finder).to respond_to :call
    end

    it "can call service provider metadata persister" do
      expect(subject.service_provider.metadata_persister).to respond_to :call
    end

    it 'has a valid session_expiry' do
      expect(subject.session_expiry).to eq(0)
    end

    context "logger initialization" do
      context 'when Rails has been properly initialized' do
        before do
          stub_const("Rails", double(logger: double("Rails.logger")))
        end

        it 'sets logger to Rails.logger' do
          expect(subject.logger).to eq(Rails.logger)
        end
      end

      context 'when Rails is not fully initialized' do
        before do
          stub_const("Rails", Class.new)          
        end

        it 'sets logger to a lambda' do
          expect(subject.logger).to be_a(Proc)
          expect { subject.logger.call("test") }.to output("test\n").to_stdout
        end
      end

      context 'when Rails is not defined' do
        it 'sets logger to a lambda' do
          hide_const("Rails")

          expect(subject.logger).to be_a(Proc)
          expect { subject.logger.call("test") }.to output("test\n").to_stdout
        end
      end

      after do
        hide_const("Rails")
      end
    end
  end
end
