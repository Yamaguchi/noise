# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::Cipher::ChaChaPoly do
  describe '#encrypt' do
    let(:cipher) { Noise::Functions::Cipher::ChaChaPoly.new }
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
    subject { cipher.encrypt(k, n, ad, plaintext).bth }
    it { is_expected.to eq ciphertext }
  end

  describe '#decrypt' do
    let(:cipher) { Noise::Functions::Cipher::ChaChaPoly.new }
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
    subject { cipher.decrypt(k, n, ad, ciphertext).bth }
    it { is_expected.to eq plaintext }
  end
end
