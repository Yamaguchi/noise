# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Protocol do
  describe '.create' do
    subject { described_class.create(name) }

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
      it { expect(subject.name).to eq name }
      it { expect(subject.protocol_name).to be_a Noise::ProtocolName }
    end

    context 'a name whose modifiers the pattern has to apply' do
      let(:name) { 'Noise_NNpsk0_25519_AESGCM_SHA256' }

      it { expect(subject.psk?).to be true }
      it { expect(subject.pattern.psk_count).to eq 1 }
    end

    context 'Invalie_Protocol_Prefix' do
      let(:name) { 'Invalie_Protocol_Prefix' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    context 'wrong prefix' do
      let(:name) { 'NoiseX_NN_25519_AESGCM_SHA256' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    context 'too few components' do
      let(:name) { 'Noise' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    context 'too many components' do
      let(:name) { 'Noise_NN_25519_AESGCM_SHA256_EXTRA' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    context 'unknown pattern' do
      let(:name) { 'Noise_ZZ_25519_AESGCM_SHA256' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    context 'empty pattern name' do
      let(:name) { 'Noise__25519_AESGCM_SHA256' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    context 'unknown modifier' do
      let(:name) { 'Noise_NNfoo_25519_AESGCM_SHA256' }

      it { expect { subject }.to raise_error Noise::Exceptions::UnsupportedModifierError }
    end

    context 'unknown dh function' do
      let(:name) { 'Noise_NN_9999_AESGCM_SHA256' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    # A hybrid name parses, and is rejected here rather than by the parser, because it is the set
    # of DH functions this gem implements that makes it unsupported. A stray '+' is rejected the
    # same way, and not read as the single function written next to it.
    context 'a dh part this gem cannot resolve' do
      ['Noise_NN_25519+448_AESGCM_SHA256', 'Noise_NN_25519+_AESGCM_SHA256',
       'Noise_NN__AESGCM_SHA256'].each do |unsupported|
        context unsupported do
          let(:name) { unsupported }

          it {
            expect { subject }
              .to raise_error Noise::Exceptions::ProtocolNameError, "Unsupported function in: #{unsupported}"
          }
        end
      end
    end

    context 'unknown cipher function' do
      let(:name) { 'Noise_NN_25519_UNKNOWN_SHA256' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end

    context 'unknown hash function' do
      let(:name) { 'Noise_NN_25519_AESGCM_UNKNOWN' }

      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end
  end
end
