# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

RSpec.describe Noise::State::CipherState do
  let(:state) do
    described_class.new(cipher: Noise::Functions::Cipher::ChaChaPoly.new).tap { |s| s.initialize_key(key) }
  end
  let(:key) { ('01' * 32).htb }

  describe '#nonce=' do
    context 'with a value in the unsigned 64-bit range' do
      it 'makes the next encryption use that nonce' do
        state.nonce = 5
        ciphertext = state.encrypt_with_ad('', 'message')

        other = described_class.new(cipher: Noise::Functions::Cipher::ChaChaPoly.new)
        other.initialize_key(key)
        other.nonce = 5
        expect(other.decrypt_with_ad('', ciphertext)).to eq 'message'
        expect(state.n).to eq 6
      end
    end

    context 'with the maximum nonce' do
      it 'is accepted, and the encryption that follows is the one that fails' do
        state.nonce = described_class::MAX_NONCE
        expect(state.n).to eq described_class::MAX_NONCE
        expect { state.encrypt_with_ad('', 'message') }.to raise_error(Noise::Exceptions::MaxNonceError)
      end
    end

    context 'with a value above the unsigned 64-bit range' do
      it 'is rejected instead of producing a truncated nonce' do
        expect { state.nonce = 2**64 }.to raise_error(Noise::Exceptions::InvalidNonceError)
        expect(state.n).to eq 0
      end
    end

    context 'with a negative value' do
      it { expect { state.nonce = -1 }.to raise_error(Noise::Exceptions::InvalidNonceError) }
    end

    context 'with a value that is not an integer' do
      it { expect { state.nonce = 1.0 }.to raise_error(Noise::Exceptions::InvalidNonceError) }
    end
  end

  describe '#rekey' do
    it 'replaces the key and keeps the nonce' do
      state.nonce = 3
      expect { state.rekey }.to change(state, :k)
      expect(state.n).to eq 3
    end
  end
end
