# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::DH::ED25519 do
  # https://tools.ietf.org/html/rfc7748#section-6.1
  describe '#dh' do
    let(:private_key) do
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'.htb
    end
    let(:public_key) do
      'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'.htb
    end
    let(:shared_key) do
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
    end
    let(:ed25519) { Noise::Functions::DH::ED25519.new }
    subject { ed25519.dh(private_key, public_key).bth }
    it { is_expected.to eq shared_key }
  end
end
