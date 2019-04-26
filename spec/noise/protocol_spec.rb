# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Protocol do
  describe '.create' do
    subject { Noise::Protocol.create(name, keypairs) }

    let(:keypairs) { { s: nil, e: nil, rs: nil, re: nil } }

    context 'Noise_NN_448_ChaChaPoly_SHA512' do
      let(:name) { 'Noise_NN_448_ChaChaPoly_SHA512' }
      it { expect(subject.cipher_fn).to be_a Noise::Functions::Cipher::ChaChaPoly }
      it { expect(subject.dh_fn).to be_a Noise::Functions::DH::ED448 }
      it { expect(subject.hash_fn).to be_a Noise::Functions::Hash::Sha512 }
    end
    context 'Noise_KN_25519_AESGCM_SHA256' do
      let(:name) { 'Noise_KN_25519_AESGCM_SHA256' }
      it { expect(subject.cipher_fn).to be_a Noise::Functions::Cipher::AesGcm }
      it { expect(subject.dh_fn).to be_a Noise::Functions::DH::ED25519 }
      it { expect(subject.hash_fn).to be_a Noise::Functions::Hash::Sha256 }
    end
    context 'Invalie_Protocol_Prefix' do
      let(:name) { 'Invalie_Protocol_Prefix' }
      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end
  end

  describe '#validate' do
    subject { protocol.validate }

    let(:protocol) { Noise::Protocol.create(name, keypairs) }
    let(:keypairs) { { s: nil, e: nil, rs: nil, re: nil } }

    context 'psk' do
      context 'valid' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

        before do
          protocol.initiator = true
          protocol.psks = [('00' * 32).htb, ('00' * 32).htb]
        end
        it { is_expected.to eq true }
      end

      context 'too long psk' do
        let(:name) { 'Noise_KNpsk0_25519_AESGCM_SHA256' }
        before { protocol.psks = [('00' * 33).htb] }
        it { expect { subject }.to raise_error(Noise::Exceptions::NoisePSKError) }
      end

      context 'unmatch psk type' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }
        before { protocol.psks = [('00' * 32).htb] }
        it { expect { subject }.to raise_error(Noise::Exceptions::NoisePSKError) }
      end
    end

    context 'non-psk' do
      let(:name) { 'Noise_KN_25519_AESGCM_SHA256' }
      let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

      context 'valid' do
        before do
          protocol.initiator = true
        end
        it { is_expected.to eq true }
      end

      context 'not initialized' do
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoiseValidationError) }
      end

      context 'unmatch key pair' do
        let(:keypairs) { { s: nil, e: ('00' * 32).htb, rs: nil, re: nil } }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoiseValidationError) }
      end
    end
  end
end
