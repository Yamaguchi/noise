# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::Hash::Blake2s do
  describe 'blake2s_hash' do
    subject { Noise::Functions::Hash::Blake2sDigester.new(key: key).update(data).digest.bth }

    describe 'abc' do
      let(:data) { 'abc' }
      let(:key) { ''.htb }
      let(:response) { '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982' }
      it { is_expected.to eq response }
    end

    describe 'abc with key' do
      let(:data) { 'abc' }
      let(:key) { 'test' }
      let(:response) { 'd0721015b3b891caff5bc6b7f88954479f9ff94abff6e8be199efcc66e120fc3' }
      it { is_expected.to eq response }
    end

    describe 'empty' do
      let(:data) { ''.htb }
      let(:key) { ''.htb }
      let(:response) { '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9' }
      it { is_expected.to eq response }
    end

    # https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt
    describe 'test vector' do
      require 'json'
      path = 'spec/vectors/blake2s-kat.txt'
      vectors = JSON.parse(File.read(path), symbolize_names: true)
      vectors.each do |json|
        describe json[:in].to_s do
          let(:data) { json[:in].htb }
          let(:key) { json[:key].htb }
          let(:response) { json[:hash] }
          it { is_expected.to eq response }
        end
      end
    end
  end
end
