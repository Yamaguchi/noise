# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::Functions::DH::ED25519 do
  # https://tools.ietf.org/html/rfc7748#section-6.1
  describe '#dh' do
    subject { ed25519.dh(private_key, public_key).bth }

    let(:private_key) do
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'.htb
    end
    let(:public_key) do
      'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'.htb
    end
    let(:shared_key) do
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
    end
    let(:ed25519) { described_class.new }

    it { is_expected.to eq shared_key }
  end

  describe '#dh with an invalid public key' do
    let(:private_key) do
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'.htb
    end
    let(:ed25519) { described_class.new }

    context 'with an all-zero public key' do
      let(:public_key) { ('00' * 32).htb }

      it {
        expect { ed25519.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end

    context 'with a low order public key' do
      # Point of order 8 listed in https://cr.yp.to/ecdh.html#validate
      let(:public_key) do
        'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'.htb
      end

      it {
        expect { ed25519.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end

    context 'with a public key shorter than dhlen' do
      let(:public_key) { ('01' * 31).htb }

      it {
        expect { ed25519.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end

    context 'with a public key longer than dhlen' do
      let(:public_key) { ('01' * 33).htb }

      it {
        expect { ed25519.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end
  end

  # The public key length is validated by #dh itself, so an error about the private key
  # still comes straight from RbNaCl instead of being reported as a public key problem.
  describe '#dh with an invalid private key' do
    let(:private_key) { ('01' * 31).htb }
    let(:public_key) do
      'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'.htb
    end
    let(:ed25519) { described_class.new }

    it { expect { ed25519.dh(private_key, public_key) }.to raise_error RbNaCl::LengthError }
  end

  describe '#generate_keypair' do
    let(:dh) { described_class.new }
    let(:alice) { dh.generate_keypair }
    let(:bob) { dh.generate_keypair }

    it { expect(dh.dh(alice.private_key, bob.public_key)).to eq dh.dh(bob.private_key, alice.public_key) }
  end
end
