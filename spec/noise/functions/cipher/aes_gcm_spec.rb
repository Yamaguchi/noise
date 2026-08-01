# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::Functions::Cipher::AesGcm do
  describe '#encrypt' do
    subject { cipher.encrypt(k, n, ad, plaintext).bth }

    let(:cipher) { described_class.new }
    let(:ad) { '955030590f203ad8e879746b277d16f8009661b332620edf641f7fe4c05a4f76'.htb }
    let(:plaintext) { '6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a'.htb }
    let(:k) { '3f9e4cb3ec38f75adf64eed6acbea18d5aceaa3742b55f30282eb6c8ec945c53'.htb }
    let(:n) { 1 }
    let(:ciphertext) do
      '99e0eed98437100ab575e5aa157f20ae23f024a43c58628646991c47e81e64af9c46165872069c5794e99a6d11614298'
    end

    it { is_expected.to eq ciphertext }
  end

  describe '#decrypt' do
    subject { cipher.decrypt(k, n, ad, ciphertext).bth }

    let(:cipher) { described_class.new }
    let(:ad) { '955030590f203ad8e879746b277d16f8009661b332620edf641f7fe4c05a4f76'.htb }
    let(:ciphertext) do
      '99e0eed98437100ab575e5aa157f20ae23f024a43c58628646991c47e81e64af9c46165872069c5794e99a6d11614298'.htb
    end
    let(:k) { '3f9e4cb3ec38f75adf64eed6acbea18d5aceaa3742b55f30282eb6c8ec945c53'.htb }
    let(:n) { 1 }
    let(:plaintext) { '6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a' }

    it { is_expected.to eq plaintext }
  end

  describe '#rekey' do
    subject { cipher.rekey(k) }

    let(:cipher) { described_class.new }
    let(:k) { '36b4b54fdef654f67adface4d65b1be19880031bdad72dff5909b9e63a4dcb68'.htb }

    it { expect(subject.bytesize).to eq 32 }

    it {
      expect(subject.bth).to eq 'fa6389ae59ea478a40fd68b33ec2273573090b6492d8d90f604d283ed6d2e338'
    }
  end

  # A Noise message frequently carries a zero-length payload.
  describe 'empty plaintext' do
    subject { cipher.encrypt(k, n, ad, '') }

    let(:cipher) { described_class.new }
    let(:ad) { '955030590f203ad8e879746b277d16f8009661b332620edf641f7fe4c05a4f76'.htb }
    let(:k) { '3f9e4cb3ec38f75adf64eed6acbea18d5aceaa3742b55f30282eb6c8ec945c53'.htb }
    let(:n) { 1 }

    it { expect(subject.bytesize).to eq 16 }
    it { expect(cipher.decrypt(k, n, ad, subject)).to eq '' }
  end
end
