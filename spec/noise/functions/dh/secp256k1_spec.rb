# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::Functions::DH::Secp256k1 do
  # https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#initiator-tests
  describe '#dh' do
    subject { secp256k1.dh(private_key, public_key).bth }

    let(:private_key) do
      '1212121212121212121212121212121212121212121212121212121212121212'.htb
    end
    let(:public_key) do
      '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7'.htb
    end
    let(:shared_key) do
      '1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3'
    end
    let(:secp256k1) { described_class.new }

    it { is_expected.to eq shared_key }
  end

  describe '#dh with an invalid public key' do
    let(:private_key) do
      '1212121212121212121212121212121212121212121212121212121212121212'.htb
    end
    let(:secp256k1) { described_class.new }

    context 'with a point that is not on the curve' do
      let(:public_key) { "02#{'00' * 32}".htb }

      it {
        expect { secp256k1.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end

    context 'with a public key shorter than dhlen' do
      let(:public_key) { ('01' * 32).htb }

      it {
        expect { secp256k1.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end

    context 'with an uncompressed public key' do
      # libsecp256k1 accepts the 65-byte form, but Noise exchanges only the compressed one.
      let(:public_key) do
        point = ECDSA::Format::PointOctetString.decode(
          '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7'.htb,
          ECDSA::Group::Secp256k1
        )
        ECDSA::Format::PointOctetString.encode(point, compression: false)
      end

      it {
        expect { secp256k1.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end
  end

  describe '#dh and generate_keypair' do
    let(:secp256k1) { described_class.new }
    let(:alice) { secp256k1.generate_keypair }
    let(:bob) { secp256k1.generate_keypair }

    it { expect(secp256k1.dh(alice.private_key, bob.public_key)).to eq secp256k1.dh(bob.private_key, alice.public_key) }
  end
end
