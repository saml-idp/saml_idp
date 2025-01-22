module SamlIdp
  module Algorithmable
    def algorithm
      return raw_algorithm if raw_algorithm.respond_to?(:digest)
      begin
        OpenSSL::Digest.const_get(raw_algorithm.to_s.upcase)
      rescue NameError
        OpenSSL::Digest::SHA1
      end
    end
    private :algorithm

    def algorithm_name
      algorithm.to_s.split('::').last.downcase
    end
    private :algorithm_name
  end
end
