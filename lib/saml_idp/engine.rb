# encoding: utf-8
module SamlIdp
  class Engine < Rails::Engine
  end

  def self.warn_for_deprecated_rails
    if defined?(Rails) && Rails.version.split('.').map(&:to_i)[0..1].join.to_i < 52
      warn "You are running a deprecated version of Rails, saml_idp might remove support for older rails (< 5.2) in upcoming release."
    end
  end
end

SamlIdp.warn_for_deprecated_rails
