# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::DH::Secp256k1 do
  # https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#initiator-tests
  describe '#dh' do
    let(:private_key) do
      '1212121212121212121212121212121212121212121212121212121212121212'.htb
    end
    let(:public_key) do
      '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7'.htb
    end
    let(:shared_key) do
      '1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3'
    end
    let(:secp256k1) { Noise::Functions::DH::Secp256k1.new }
    subject { secp256k1.dh(private_key, public_key).bth }
    it { is_expected.to eq shared_key }
  end

  describe '#dh and generate_keypair' do
    let(:secp256k1) { Noise::Functions::DH::Secp256k1.new }
    let(:alice) { secp256k1.generate_keypair }
    let(:bob) { secp256k1.generate_keypair }

    it { expect(secp256k1.dh(alice[0], bob[1])).to eq secp256k1.dh(bob[0], alice[1]) }
  end
end
