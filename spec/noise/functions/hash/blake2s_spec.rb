# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::Hash::Blake2s do
  describe 'blake2s_hash' do
    subject { Noise::Functions::Hash::Blake2sDigester.new(key: key).update(data).digest.bth }

    describe 'abc' do
      let(:data) { "abc" }
      let(:key) { "".htb }
      let(:response) { "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982" }
      it { is_expected.to eq response }
    end

    describe 'abc with key' do
      let(:data) { "abc" }
      let(:key) { "test" }
      let(:response) { "d0721015b3b891caff5bc6b7f88954479f9ff94abff6e8be199efcc66e120fc3" }
      it { is_expected.to eq response }
    end

    # https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt
    describe '00' do
      let(:data) { "00".htb }
      let(:key) { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".htb }
      let(:response) { "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1" }
      it { is_expected.to eq response }
    end

    describe 'empty' do
      let(:data) { "".htb }
      let(:key) { "".htb }
      let(:response) { "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9" }
      it { is_expected.to eq response }
    end

    describe 'long data' do
      let(:data) do
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' \
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' \
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' \
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' \
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf' \
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' \
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe'.htb
      end
      let(:key) { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".htb }
      let(:response) { "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd" }
      it { is_expected.to eq response }
    end
  end
end