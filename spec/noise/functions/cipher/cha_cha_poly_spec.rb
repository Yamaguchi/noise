# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::Functions::Cipher::ChaChaPoly do
  describe '#encrypt' do
    subject { cipher.encrypt(k, n, ad, plaintext).bth }

    let(:cipher) { described_class.new }
    let(:ad) do
      'f19cda578a38f47ffef8844a7568a5900b28351a7882c7a294ae45d154827b39' \
      'b3516a076ff383654107a0f477d501ad921e111da06f96dc6bd9e8b0c4eca800'.htb
    end
    let(:plaintext) { '6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a'.htb }
    let(:k) { '36b4b54fdef654f67adface4d65b1be19880031bdad72dff5909b9e63a4dcb68'.htb }
    let(:n) { 1 }
    let(:ciphertext) do
      'ec9136de99472b49eda3ba9fe84882d48f131b27386784b3f45e9f103ad1b6efa2f2e95f0afce5d0d4c8052aed814385'
    end

    it { is_expected.to eq ciphertext }
  end

  describe '#decrypt' do
    subject { cipher.decrypt(k, n, ad, ciphertext).bth }

    let(:cipher) { described_class.new }
    let(:ad) do
      'f19cda578a38f47ffef8844a7568a5900b28351a7882c7a294ae45d154827b39' \
      'b3516a076ff383654107a0f477d501ad921e111da06f96dc6bd9e8b0c4eca800'.htb
    end
    let(:ciphertext) do
      'ec9136de99472b49eda3ba9fe84882d48f131b27386784b3f45e9f103ad1b6efa2f2e95f0afce5d0d4c8052aed814385'.htb
    end
    let(:k) { '36b4b54fdef654f67adface4d65b1be19880031bdad72dff5909b9e63a4dcb68'.htb }
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
      expect(subject.bth).to eq '3a1fd0e0f2af6b92dd0cf922fb60d0da2cb83cd92ea9c586100be673ef260af6'
    }
  end

  # A Noise message frequently carries a zero-length payload.
  describe 'empty plaintext' do
    subject { cipher.encrypt(k, n, ad, '') }

    let(:cipher) { described_class.new }
    let(:ad) { '955030590f203ad8e879746b277d16f8009661b332620edf641f7fe4c05a4f76'.htb }
    let(:k) { '36b4b54fdef654f67adface4d65b1be19880031bdad72dff5909b9e63a4dcb68'.htb }
    let(:n) { 1 }

    it { expect(subject.bytesize).to eq 16 }
    it { expect(cipher.decrypt(k, n, ad, subject)).to eq '' }
  end

  # A ciphertext that fails the Poly1305 check must be reported as the library's own DecryptError,
  # not as the OpenSSL error underneath it.
  describe 'tampered ciphertext' do
    subject { cipher.decrypt(k, n, ad, tampered) }

    let(:cipher) { described_class.new }
    let(:ad) { '955030590f203ad8e879746b277d16f8009661b332620edf641f7fe4c05a4f76'.htb }
    let(:k) { '36b4b54fdef654f67adface4d65b1be19880031bdad72dff5909b9e63a4dcb68'.htb }
    let(:n) { 1 }
    let(:tampered) do
      ciphertext = cipher.encrypt(k, n, ad, 'hello')
      ciphertext[0] = (ciphertext[0].ord ^ 0x01).chr
      ciphertext
    end

    it { expect { subject }.to raise_error Noise::Exceptions::DecryptError }
  end
end
