# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::State::SymmetricState do
  let(:state) do
    Noise::State::SymmetricState.new.tap do |state|
      state.initialize_symmetric(Noise::Protocol.create('Noise_XKpsk3_25519_ChaChaPoly_SHA256'))
    end
  end
  describe '#initialize_symmetric' do
    subject { state }
    let(:expected) { 'b4ac732ebf6d89e36c61a61dc5eaf91dbd600e33bcc0b9f02f800cbfd8ea31c3'.htb }
    it { expect(subject.h).to eq expected }
  end

  describe '#mix_hash' do
    let(:data) { '4a6f686e2047616c74'.htb }
    subject { state.tap { |s| s.mix_hash(data) } }
    let(:expected) { 'c55808d73021fad5a1b1a156c4fa2bb066e8f531760870fd11796f1ee93ff6c8' }
    it { expect(subject.h.bth).to eq expected }
  end

  describe '#mix_key' do
    let(:input_key_material) { 'ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944'.htb }
    subject { state.tap { |s| s.mix_key(input_key_material) } }
    let(:expected_ck) { 'b1b4bfa59962831316526441a31fc6255873c42b55610b997f2403241a6e4655' }
    let(:expected_k) { '34423d0b96515cca3ca861f8e8960b492e3343f23273b3655a567fd11f0dfa7d' }
    it { expect(subject.ck.bth).to eq expected_ck }
    it { expect(subject.cipher_state.k.bth).to eq expected_k }
  end

  # describe '#encrypt_and_hash' do
  #   let(:state) do
  #     Noise::State::SymmetricState.new.tap do |state|
  #       state.initialize_symmetric(Noise::Protocol.create('Noise_NN_25519_ChaChaPoly_SHA256'))
  #     end
  #   end
  #   let(:plaintext) { '4d757272617920526f746862617264'.htb }
  #   let(:h) { '507eb1fe01fd7c4fe1829ef6a07f38340b4a72e6dffbb3ffb0f9209271775b4e'.htb }
  #   let(:expected) { 'a0ff96bdf86b579ef7dbf94e812a7470b903c20a85a87e3a1fe863264ae547'.htb }
  #   it { expect(subject.encrypt_and_hash(plaintext).bth).to eq expected.bth }
  # end
end
