# frozen_string_literal: true

# The interoperability suite runs outside `bundle exec rspec`, so it loads the gem straight from
# lib/ and skips the coverage reporting the main suite sets up. It has no dependency on
# spec/spec_helper.rb.
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'noise'

RSpec.configure do |config|
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
