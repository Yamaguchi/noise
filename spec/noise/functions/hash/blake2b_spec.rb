# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::Functions::Hash::Blake2b do
  describe '#hash' do
    subject { described_class.new.hash(data).bth }

    # https://datatracker.ietf.org/doc/html/rfc7693#appendix-A
    context 'with abc' do
      let(:data) { 'abc' }
      let(:expected) do
        'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1' \
        '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'
      end

      it { is_expected.to eq expected }
    end

    context 'with an empty input' do
      let(:data) { ''.htb }
      let(:expected) do
        '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419' \
        'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
      end

      it { is_expected.to eq expected }
    end
  end

  describe '#hashlen' do
    it { expect(described_class.new.hashlen).to eq 64 }
  end

  describe '#blocklen' do
    it { expect(described_class.new.blocklen).to eq 128 }
  end

  describe Noise::Functions::Hash::Blake2bHMAC do
    describe '#digest' do
      subject { described_class.new(key).update(data).digest.bth }

      let(:key) { '2b0abd71cb6e7fcc623d554c22b31e90989bddf88690a6e1eeaeafc6004a1a6a'.htb }
      let(:data) { '6e6ceaad64c8cd4607e91ba6009c6384c708d0383e202a11c31dcd678a0f45f402'.htb }
      let(:expected) do
        'ae20f7ca0813f641a539929137c01db7ce833aea9bfa3f56da7ca35b7df05983' \
        'eadaf5a748f79be9f0c7ee1476246c455cf391b3e7ab29cf81705051c39dbc71'
      end

      it { is_expected.to eq expected }

      # The HMAC construction hashes a key longer than the block size down to a single digest, and
      # that is the only path that calls Blake2bDigester.digest as a class method. The expected
      # value is the one OpenSSL::HMAC produces for the same key and data, so this path is checked
      # against the standard HMAC definition rather than against itself.
      context 'with a key longer than the block size' do
        let(:key) { ('01' * 129).htb }
        let(:expected) do
          '13c0f66257aad27f59b52b81376a6bc163da88df51c9166ee863f7dee9f4c771' \
          '870a63338dfd3dc578ae9e4df09cec35a1c551c1ff767dba5cbe11742891ebe5'
        end

        it { is_expected.to eq expected }
      end
    end
  end
end
