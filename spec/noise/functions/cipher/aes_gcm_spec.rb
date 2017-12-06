# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::Cipher::AesGcm do
  describe '#encrypt' do
    let(:cipher) { Noise::Functions::Cipher::AesGcm.new }
    let(:ad) { '955030590f203ad8e879746b277d16f8009661b332620edf641f7fe4c05a4f76'.htb }
    let(:plaintext) { '6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a'.htb }
    let(:k) { '3f9e4cb3ec38f75adf64eed6acbea18d5aceaa3742b55f30282eb6c8ec945c53'.htb }
    let(:n) { "\x00\x00\x00\x00" + "\x00\x00\x00\x00\x00\x00\x00\x01" } # Big endian
    let(:ciphertext) do
      '99e0eed98437100ab575e5aa157f20ae23f024a43c58628646991c47e81e64af9c46165872069c5794e99a6d11614298'
    end
    subject { cipher.encrypt(k, n, ad, plaintext).bth }
    it { is_expected.to eq ciphertext }
  end

  describe '#decrypt' do
    let(:cipher) { Noise::Functions::Cipher::AesGcm.new }
    let(:ad) { '955030590f203ad8e879746b277d16f8009661b332620edf641f7fe4c05a4f76'.htb }
    let(:ciphertext) do
      '99e0eed98437100ab575e5aa157f20ae23f024a43c58628646991c47e81e64af9c46165872069c5794e99a6d11614298'.htb
    end
    let(:k) { '3f9e4cb3ec38f75adf64eed6acbea18d5aceaa3742b55f30282eb6c8ec945c53'.htb }
    let(:n) { "\x00\x00\x00\x00" + "\x00\x00\x00\x00\x00\x00\x00\x01" } # Big endian
    let(:plaintext) { '6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a' }
    subject { cipher.decrypt(k, n, ad, ciphertext).bth }
    it { is_expected.to eq plaintext }
  end
end
