# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::Functions::DH::ED448 do
  # https://tools.ietf.org/html/rfc7748#section-6.2
  describe '#dh' do
    subject { ed448.dh(private_key, public_key).bth }

    let(:private_key) do
      '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d' \
      'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'.htb
    end
    let(:public_key) do
      '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430' \
      '27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609'.htb
    end
    let(:shared_key) do
      '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b' \
      'b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d'
    end
    let(:ed448) { described_class.new }

    it { is_expected.to eq shared_key }
  end

  describe '#dh with an invalid public key' do
    let(:private_key) do
      '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d' \
      'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'.htb
    end
    let(:ed448) { described_class.new }

    context 'with an all-zero public key' do
      let(:public_key) { ('00' * 56).htb }

      it {
        expect { ed448.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end

    context 'with a public key shorter than dhlen' do
      let(:public_key) { ('01' * 55).htb }

      it {
        expect { ed448.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end

    context 'with a public key longer than dhlen' do
      let(:public_key) { ('01' * 57).htb }

      it {
        expect { ed448.dh(private_key, public_key) }
          .to raise_error Noise::Exceptions::InvalidPublicKeyError
      }
    end
  end

  # A key the caller owns is not a peer-supplied one, so a malformed private key must not be
  # reported as the remote party's fault.
  describe '#dh with an invalid private key' do
    let(:ed448) { described_class.new }
    let(:public_key) do
      '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430' \
      '27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609'.htb
    end

    it 'does not translate the error into InvalidPublicKeyError' do
      expect { ed448.dh(('01' * 55).htb, public_key) }
        .to raise_error OpenSSL::PKey::PKeyError
    end
  end

  describe '.from_private' do
    # https://tools.ietf.org/html/rfc7748#section-6.2, Alice's key pair.
    let(:private_key) do
      '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d' \
      'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'.htb
    end
    let(:public_key) do
      '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c' \
      '22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0'
    end

    it { expect(described_class.from_private(private_key).public_key.bth).to eq public_key }
    it { expect(described_class.from_private(private_key).private_key).to eq private_key }
  end

  describe '#generate_keypair' do
    let(:dh) { described_class.new }
    let(:alice) { dh.generate_keypair }
    let(:bob) { dh.generate_keypair }

    it { expect(dh.dh(alice.private_key, bob.public_key)).to eq dh.dh(bob.private_key, alice.public_key) }
  end
end
