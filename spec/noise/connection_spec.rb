# frozen_string_literal: true

require 'spec_helper'

using Noise::Utils::HexString

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

  describe '#start_handshake' do
    let(:connection) { Noise::Connection::Initiator.new('Noise_NN_25519_AESGCM_SHA256') }

    before { connection.start_handshake }

    it 'copies the message patterns instead of sharing them with the protocol pattern' do
      tokens = connection.protocol.pattern.tokens
      expect(connection.handshake_state.message_patterns).to eq tokens
      expect(connection.handshake_state.message_patterns.first).not_to equal tokens.first
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

  describe 'transport nonce' do
    let(:name) { 'Noise_NN_25519_AESGCM_SHA256' }
    let(:initiator) { Noise::Connection::Initiator.new(name) }
    let(:responder) { Noise::Connection::Responder.new(name) }

    before do
      initiator.start_handshake
      responder.start_handshake
      responder.read_message(initiator.write_message(''))
      initiator.read_message(responder.write_message(''))
    end

    it 'starts at zero and counts the transport messages' do
      expect(initiator.encryption_nonce).to eq 0
      initiator.encrypt('first')
      expect(initiator.encryption_nonce).to eq 1
      expect(responder.decryption_nonce).to eq 0
    end

    it 'lets the receiver decrypt messages that arrive out of order' do
      first = initiator.encrypt('first')
      second = initiator.encrypt('second')

      responder.decryption_nonce = 1
      expect(responder.decrypt(second)).to eq 'second'
      responder.decryption_nonce = 0
      expect(responder.decrypt(first)).to eq 'first'
    end

    it 'rejects a nonce outside the unsigned 64-bit range' do
      expect { responder.decryption_nonce = 2**64 }.to raise_error(Noise::Exceptions::InvalidNonceError)
      expect { initiator.encryption_nonce = -1 }.to raise_error(Noise::Exceptions::InvalidNonceError)
      expect(responder.decryption_nonce).to eq 0
    end

    context 'before the handshake finishes' do
      let(:fresh) { Noise::Connection::Initiator.new(name) }

      it { expect { fresh.encryption_nonce = 1 }.to raise_error(Noise::Exceptions::NoiseHandshakeError) }
      it { expect { fresh.decryption_nonce }.to raise_error(Noise::Exceptions::NoiseHandshakeError) }
    end
  end

  describe 'transport rekey' do
    let(:name) { 'Noise_NN_25519_AESGCM_SHA256' }
    let(:initiator) { Noise::Connection::Initiator.new(name) }
    let(:responder) { Noise::Connection::Responder.new(name) }

    before do
      initiator.start_handshake
      responder.start_handshake
      responder.read_message(initiator.write_message(''))
      initiator.read_message(responder.write_message(''))
    end

    it 'keeps both parties in sync when the matching directions rekey' do
      initiator.rekey_encryption
      responder.rekey_decryption

      expect(responder.decrypt(initiator.encrypt('after rekey'))).to eq 'after rekey'
    end

    it 'does not reset the nonce' do
      initiator.encrypt('first')
      initiator.rekey_encryption

      expect(initiator.encryption_nonce).to eq 1
    end

    it 'makes the message undecryptable for a receiver that did not rekey' do
      initiator.rekey_encryption

      expect { responder.decrypt(initiator.encrypt('after rekey')) }
        .to raise_error(Noise::Exceptions::DecryptError)
    end
  end

  describe 'one-way pattern' do
    let(:name) { 'Noise_N_25519_AESGCM_SHA256' }
    let(:static) { Noise::Protocol.create(name).dh_fn.class.from_private(('11' * 32).htb) }
    let(:initiator) { Noise::Connection::Initiator.new(name, keypairs: { rs: static.public_key }) }
    let(:responder) { Noise::Connection::Responder.new(name, keypairs: { s: static.private_key }) }

    before do
      initiator.start_handshake
      responder.start_handshake
      responder.read_message(initiator.write_message(''))
    end

    it 'has no cipher state for the direction the party cannot use' do
      expect { initiator.rekey_decryption }
        .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'This party cannot decrypt messages.')
      expect { initiator.decrypt('') }
        .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'This party cannot decrypt messages.')
      expect { responder.rekey_encryption }
        .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'This party cannot encrypt messages.')
      expect { responder.encryption_nonce }
        .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'This party cannot encrypt messages.')
    end
  end
end
