# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::Functions::Hash::Blake3 do
  describe '#hash' do
    subject { described_class.new.hash(data).bth }

    describe 'empty' do
      let(:data) { ''.htb }

      it { is_expected.to eq 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262' }
    end

    describe 'abc' do
      let(:data) { 'abc' }

      it { is_expected.to eq '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85' }
    end

    # https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    describe 'test vector' do
      path = 'spec/vectors/blake3-kat.txt'
      vectors = JSON.parse(File.read(path), symbolize_names: true)
      vectors.each do |json|
        describe "input of #{json[:input_len]} bytes" do
          # The upstream file states the input as a rule rather than as bytes: input_len bytes of
          # the repeating sequence 0, 1, 2, ..., 250, 0, 1, and so on.
          let(:data) { Array.new(json[:input_len]) { |i| i % 251 }.pack('C*') }
          let(:response) { json[:hash] }

          it { is_expected.to eq response }
        end
      end
    end
  end

  describe '#hashlen and #blocklen' do
    # HMAC and HKDF depend on these matching the digest, so they are checked against the gem rather
    # than restated as literals.
    it { expect(described_class.new.hashlen).to eq Digest::Blake3.new.digest_length }
    it { expect(described_class.new.blocklen).to eq Digest::Blake3.new.block_length }
  end

  # BLAKE3 has no published HMAC vectors, so the expected values come from an independent RFC 2104
  # implementation over Digest::Blake3, written without ruby-hmac.
  describe Noise::Functions::Hash::Blake3HMAC do
    subject { described_class.new(key).update(data).digest.bth }

    context 'with an empty key and empty data' do
      let(:key) { ''.htb }
      let(:data) { ''.htb }

      it { is_expected.to eq 'c8366b212fa0d095e99d6fe861bd554187714942aab92d9f02dbccb9d896e219' }
    end

    context 'with a key shorter than the block length' do
      let(:key) { 'key' }
      let(:data) { 'The quick brown fox jumps over the lazy dog' }

      it { is_expected.to eq '3742da5c89b7c0c376c0af2f211bd59f97aeaa282f21dccb0c0308b7703ac959' }
    end

    context 'with a key longer than the block length' do
      let(:key) { 'a' * 100 }
      let(:data) { 'message longer than one block ' * 4 }

      it { is_expected.to eq '2e94162938e4cf1a0d4d9f6968b2ad06477696f10da4f0ceca7807908263bbc9' }
    end
  end

  # No official Noise test vector covers BLAKE3, so the backend is exercised through a full
  # handshake instead: both sides must derive the same keys and the same handshake hash.
  describe 'handshake and transport' do
    let(:name) { 'Noise_NN_25519_ChaChaPoly_BLAKE3' }
    let(:initiator) { Noise::Connection::Initiator.new(name) }
    let(:responder) { Noise::Connection::Responder.new(name) }

    before do
      initiator.start_handshake
      responder.start_handshake
      responder.read_message(initiator.write_message(''))
      initiator.read_message(responder.write_message(''))
    end

    it 'agrees on the handshake hash' do
      expect(initiator.handshake_hash).to eq responder.handshake_hash
      expect(initiator.handshake_hash.bytesize).to eq Noise::Functions::Hash::Blake3::HASHLEN
    end

    it 'carries transport messages in both directions' do
      expect(responder.decrypt(initiator.encrypt('to the responder'))).to eq 'to the responder'
      expect(initiator.decrypt(responder.encrypt('to the initiator'))).to eq 'to the initiator'
    end
  end
end
