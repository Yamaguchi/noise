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

    # OpenSSL reads this as the point at infinity and raises nothing, so without the explicit
    # check the shared secret would be a constant that whoever sent the key can precompute.
    context 'with an all-zero public key' do
      let(:public_key) { ('00' * 33).htb }

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
      # The 65-byte form names the same point, but Noise exchanges only the compressed one.
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

  # A key the caller owns is not a peer-supplied one, so a malformed private key must not be
  # reported as the remote party's fault.
  describe '#dh with an invalid private key' do
    subject { secp256k1.dh(private_key, public_key) }

    let(:secp256k1) { described_class.new }
    let(:public_key) do
      '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7'.htb
    end

    context 'with a private key shorter than a scalar' do
      let(:private_key) { ('01' * 31).htb }

      it { expect { subject }.to raise_error ArgumentError }
    end

    context 'with an all-zero private key' do
      let(:private_key) { ('00' * 32).htb }

      it { expect { subject }.to raise_error ArgumentError }
    end

    context 'with a private key that is not below the group order' do
      # The order itself multiplies every point to infinity.
      let(:private_key) do
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'.htb
      end

      it { expect { subject }.to raise_error ArgumentError }
    end
  end

  describe '.from_private' do
    # https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#initiator-tests
    let(:private_key) do
      '1111111111111111111111111111111111111111111111111111111111111111'.htb
    end
    let(:public_key) do
      '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'
    end

    it { expect(described_class.from_private(private_key).public_key.bth).to eq public_key }
    it { expect(described_class.from_private(private_key).private_key).to eq private_key }
  end

  describe '#dh and generate_keypair' do
    let(:secp256k1) { described_class.new }
    let(:alice) { secp256k1.generate_keypair }
    let(:bob) { secp256k1.generate_keypair }

    it { expect(secp256k1.dh(alice.private_key, bob.public_key)).to eq secp256k1.dh(bob.private_key, alice.public_key) }
  end
end
