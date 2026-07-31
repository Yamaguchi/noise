# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Connection do
  describe '#validate' do
    subject { connection.validate }

    let(:connection) { Noise::Connection::Initiator.new(name, keypairs: keypairs) }
    let(:keypairs) { { s: nil, e: nil, rs: nil, re: nil } }

    context 'psk' do
      context 'valid' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

        before do
          connection.psks = [('00' * 32).htb, ('00' * 32).htb]
        end

        it { is_expected.to be true }
      end

      context 'too long psk' do
        let(:name) { 'Noise_KNpsk0_25519_AESGCM_SHA256' }

        before { connection.psks = [('00' * 33).htb] }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoisePSKError) }
      end

      context 'unmatch psk type' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }

        before { connection.psks = [('00' * 32).htb] }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoisePSKError) }
      end
    end

    context 'non-psk' do
      let(:name) { 'Noise_KN_25519_AESGCM_SHA256' }
      let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

      context 'valid' do
        it { is_expected.to be true }
      end

      context 'unmatch key pair' do
        let(:keypairs) { { s: nil, e: ('00' * 32).htb, rs: nil, re: nil } }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoiseValidationError) }
      end
    end

    context 'deferred pattern' do
      let(:name) { 'Noise_X1K_25519_AESGCM_SHA256' }

      context 'valid' do
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: ('00' * 32).htb, re: nil } }

        it { is_expected.to be true }
      end

      # X1K pre-shares the responder's static key, so the initiator must know rs.
      context 'missing remote static key' do
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoiseValidationError) }
      end
    end
  end

  describe 'message length validation' do
    let(:name) { 'Noise_NN_25519_AESGCM_SHA256' }
    let(:initiator) { Noise::Connection::Initiator.new(name) }
    let(:responder) { Noise::Connection::Responder.new(name) }
    let(:message) { initiator.write_message('') }

    before do
      initiator.start_handshake
      responder.start_handshake
    end

    context 'when the handshake message is truncated' do
      it 'raises NoiseHandshakeError instead of failing on a nil slice' do
        expect { responder.read_message(message[0...10]) }
          .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'Message is too short.')
      end
    end

    context 'when the handshake message is longer than the maximum length' do
      it {
        expect { responder.read_message('a' * (described_class::Base::MAX_MESSAGE_LENGTH + 1)) }
          .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'Message exceeds the maximum length.')
      }
    end

    context 'when the payload would make the message longer than the maximum length' do
      it {
        expect { initiator.write_message('a' * described_class::Base::MAX_MESSAGE_LENGTH) }
          .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'Message exceeds the maximum length.')
      }
    end

    context 'when the transport message is shorter than the authentication tag' do
      before do
        responder.read_message(message)
        initiator.read_message(responder.write_message(''))
      end

      it {
        expect { responder.decrypt('short') }
          .to raise_error(Noise::Exceptions::DecryptError, 'Ciphertext is shorter than the tag.')
      }
    end
  end
end
