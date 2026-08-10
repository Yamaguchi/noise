# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise do
  it 'has a version number' do
    expect(Noise::VERSION).not_to be_nil
  end

  describe '.require_optional' do
    # require_optional records failures in a module level hash, so each example has to put back
    # whatever was there when the real optional backends were loaded.
    around do |example|
      saved = described_class.instance_variable_get(:@unavailable_dependencies).dup
      example.run
      described_class.instance_variable_set(:@unavailable_dependencies, saved)
    end

    it 'yields when the dependency loads' do
      expect { |b| described_class.require_optional('securerandom', &b) }.to yield_control
    end

    it 'leaves the dependency usable when it loads' do
      described_class.require_optional('securerandom')
      expect { described_class.optional_dependency!('securerandom') }.not_to raise_error
    end

    it 'warns instead of raising when the dependency is missing' do
      expect { described_class.require_optional('noise/no_such_backend') }
        .to output(%r{Optional dependency 'noise/no_such_backend' is unavailable}).to_stderr
    end

    it 'does not yield when the dependency is missing' do
      expect do |b|
        expect { described_class.require_optional('noise/no_such_backend', &b) }.to output.to_stderr
      end.not_to yield_control
    end
  end

  describe '.optional_dependency!' do
    around do |example|
      saved = described_class.instance_variable_get(:@unavailable_dependencies).dup
      example.run
      described_class.instance_variable_set(:@unavailable_dependencies, saved)
    end

    it 'raises with the recorded reason once the load has failed' do
      expect { described_class.require_optional('noise/no_such_backend') }.to output.to_stderr
      expect { described_class.optional_dependency!('noise/no_such_backend') }
        .to raise_error(Noise::Exceptions::MissingDependencyError, /could not be loaded/)
    end

    it 'does nothing for a dependency that was never recorded as failing' do
      expect { described_class.optional_dependency!('noise/never_required') }.not_to raise_error
    end
  end
end
