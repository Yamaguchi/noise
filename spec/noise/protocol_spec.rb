# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Protocol do
  describe '.create' do
    subject { Noise::Protocol.create(name) }

    context 'Noise_NN_448_ChaChaPoly_BLAKE2b' do
      let(:name) { 'Noise_NN_448_ChaChaPoly_BLAKE2b' }
      it { expect(subject.cipher_fn).to be_a Noise::Functions::Cipher::ChaChaPoly }
      it { expect(subject.dh_fn).to be_a Noise::Functions::DH::DH448 }
      it { expect(subject.hash_fn).to be_a Noise::Functions::Hash::Blake2b }
    end
    context 'Noise_KN_25519_AESGCM_SHA256' do
      let(:name) { 'Noise_KN_25519_AESGCM_SHA256' }
      it { expect(subject.cipher_fn).to be_a Noise::Functions::Cipher::AesGcm }
      it { expect(subject.dh_fn).to be_a Noise::Functions::DH::DH25519 }
      it { expect(subject.hash_fn).to be_a Noise::Functions::Hash::Sha256 }
    end
    context 'Invalie_Protocol_Name' do
      let(:name) { 'Invalie_Protocol_Name' }
      it { expect { subject }.to raise_error Noise::Exceptions::ProtocolNameError }
    end
  end
end
