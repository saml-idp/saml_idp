# frozen_string_literal: true


require 'rack/test'
require 'rspec'

require File.expand_path '../app.rb', __dir__

module RSpecMixin
  def app
    App
  end

  include Rack::Test::Methods
end

RSpec.configure do |config|
  config.include RSpecMixin
end
