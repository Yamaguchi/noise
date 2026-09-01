# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

desc 'Build the harness the interoperability suite runs against'
task :interop_harness do
  Dir.chdir('interop') { sh 'cargo build --release --locked' }
end

desc 'Run the interoperability suite against the snow reference implementation'
RSpec::Core::RakeTask.new(interop: :interop_harness) do |task|
  task.pattern = 'interop/*_spec.rb'
end

# interop is deliberately left out: it needs a Rust toolchain, and the harness built from
# interop/. See interop/README.md.
task default: :spec
