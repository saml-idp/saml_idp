require 'rubygems'
require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

desc 'Run the specs.'
task :default => :spec

task :notes do
   system "grep -n -r 'FIXME\\|TODO' lib spec"
end
