# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Protocol do
  describe '.create' do
    subject { Noise::Protocol.create(name) }

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

end
