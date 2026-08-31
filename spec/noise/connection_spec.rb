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

      # The connection is usable without psks for any other pattern, so nothing sets @psks unless
      # the caller does.
      context 'psks never set' do
        let(:name) { 'Noise_KNpsk0_25519_AESGCM_SHA256' }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoisePSKError, 'psks are not set.') }
      end

      context 'too long psk' do
        let(:name) { 'Noise_KNpsk0_25519_AESGCM_SHA256' }

        before { connection.psks = [('00' * 33).htb] }

        it {
          expect { subject }
            .to raise_error(Noise::Exceptions::NoisePSKError, 'psks have to be 32 bytes long.')
        }
      end

      context 'unmatch psk type' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }

        before { connection.psks = [('00' * 32).htb] }

        it {
          expect { subject }
            .to raise_error(Noise::Exceptions::NoisePSKError, 'This protocol needs 2 psks, got 1.')
        }
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
          .to raise_error(Noise::Exceptions::MessageTooLongError, /65536 bytes.*maximum of 65535/)
      }
    end

    context 'when the payload would make the message longer than the maximum length' do
      it {
        expect { initiator.write_message('a' * described_class::Base::MAX_MESSAGE_LENGTH) }
          .to raise_error(Noise::Exceptions::MessageTooLongError, /65567 bytes.*maximum of 65535/)
      }

      it 'leaves the connection able to write the message it rejected the payload of' do
        expect { initiator.write_message('a' * described_class::Base::MAX_MESSAGE_LENGTH) }
          .to raise_error(Noise::Exceptions::MessageTooLongError)

        expect(responder.read_message(initiator.write_message(''))).to eq ''
      end
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

    context 'when the handshake has finished' do
      let(:max_plaintext) { described_class::Base::MAX_PLAINTEXT_LENGTH }

      before do
        responder.read_message(message)
        initiator.read_message(responder.write_message(''))
      end

      it 'encrypts the longest plaintext that still fits in a maximum length message' do
        ciphertext = initiator.encrypt('a' * max_plaintext)

        expect(ciphertext.bytesize).to eq described_class::Base::MAX_MESSAGE_LENGTH
        expect(responder.decrypt(ciphertext)).to eq 'a' * max_plaintext
      end

      it 'rejects a plaintext whose ciphertext would exceed the maximum length' do
        expect { initiator.encrypt('a' * (max_plaintext + 1)) }
          .to raise_error(Noise::Exceptions::MessageTooLongError, /65520 bytes.*maximum of 65519/)

        # The rejection happens before the cipher state is touched, so the connection stays usable.
        expect(initiator.cipher_state_encrypt.n).to eq 0
        expect(responder.decrypt(initiator.encrypt('hello'))).to eq 'hello'
      end

      it 'rejects a transport message longer than the maximum length' do
        expect { responder.decrypt('a' * (described_class::Base::MAX_MESSAGE_LENGTH + 1)) }
          .to raise_error(Noise::Exceptions::MessageTooLongError, /65536 bytes.*maximum of 65535/)

        expect(responder.cipher_state_decrypt.n).to eq 0
        expect(responder.decrypt(initiator.encrypt('hello'))).to eq 'hello'
      end
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

    it 'lets the initiator send transport messages' do
      expect(responder.decrypt(initiator.encrypt('hello'))).to eq 'hello'
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
      expect { responder.encrypt('hello') }
        .to raise_error(Noise::Exceptions::NoiseHandshakeError, 'This party cannot encrypt messages.')
    end
  end

  describe 'connection state' do
    let(:name) { 'Noise_NN_25519_AESGCM_SHA256' }
    let(:initiator) { Noise::Connection::Initiator.new(name) }
    let(:responder) { Noise::Connection::Responder.new(name) }

    describe 'transitions' do
      it 'starts in :created, with neither flag set' do
        expect(initiator.state).to eq :created
        expect(initiator.handshake_started?).to be false
        expect(initiator.handshake_finished?).to be false
      end

      it 'moves each party into the state its role starts the pattern in' do
        initiator.start_handshake
        responder.start_handshake

        expect(initiator.state).to eq :handshake_write
        expect(responder.state).to eq :handshake_read
        expect(initiator.handshake_started?).to be true
        expect(initiator.handshake_finished?).to be false
      end

      it 'passes the turn on every handshake message, and ends in :transport' do
        initiator.start_handshake
        responder.start_handshake

        first = initiator.write_message('')
        expect(initiator.state).to eq :handshake_read
        responder.read_message(first)
        expect(responder.state).to eq :handshake_write

        initiator.read_message(responder.write_message(''))
        expect(initiator.state).to eq :transport
        expect(responder.state).to eq :transport
        expect(initiator.handshake_finished?).to be true
      end

      it 'keeps handshake_started and handshake_finished as aliases of the predicates' do
        initiator.start_handshake

        expect(initiator.handshake_started).to be true
        expect(initiator.handshake_finished).to be false
      end
    end

    describe 'operations called in the wrong state' do
      it 'reports a handshake that has not started' do
        expect { initiator.write_message('') }
          .to raise_error(Noise::Exceptions::HandshakeNotStartedError, /has not started/)
        expect { initiator.read_message('') }
          .to raise_error(Noise::Exceptions::HandshakeNotStartedError, /has not started/)
        expect { initiator.fallback('Noise_XXfallback_25519_AESGCM_SHA256') }
          .to raise_error(Noise::Exceptions::HandshakeNotStartedError, /has not started/)
      end

      it 'reports whose turn it is' do
        initiator.start_handshake
        responder.start_handshake

        expect { initiator.read_message('') }
          .to raise_error(Noise::Exceptions::HandshakeTurnError, /writes the next handshake message/)
        expect { responder.write_message('') }
          .to raise_error(Noise::Exceptions::HandshakeTurnError, /reads the next handshake message/)
      end

      it 'reports a handshake that has not finished when a transport operation is called' do
        initiator.start_handshake

        expect { initiator.encrypt('') }
          .to raise_error(Noise::Exceptions::HandshakeNotFinishedError, 'The handshake has not finished.')
        expect { initiator.rekey_encryption }
          .to raise_error(Noise::Exceptions::HandshakeNotFinishedError, 'The handshake has not finished.')
      end

      it 'rejects a second start_handshake' do
        initiator.start_handshake

        expect { initiator.start_handshake }
          .to raise_error(Noise::Exceptions::HandshakeTurnError, /writes the next handshake message/)
      end

      it 'reports a handshake that is already over' do
        initiator.start_handshake
        responder.start_handshake
        responder.read_message(initiator.write_message(''))
        initiator.read_message(responder.write_message(''))

        expect { initiator.start_handshake }
          .to raise_error(Noise::Exceptions::HandshakeAlreadyFinishedError, 'The handshake has already finished.')
        expect { initiator.write_message('') }
          .to raise_error(Noise::Exceptions::HandshakeAlreadyFinishedError, 'The handshake has already finished.')
        expect { initiator.read_message('') }
          .to raise_error(Noise::Exceptions::HandshakeAlreadyFinishedError, 'The handshake has already finished.')
        expect { initiator.fallback('Noise_XXfallback_25519_AESGCM_SHA256') }
          .to raise_error(Noise::Exceptions::HandshakeAlreadyFinishedError, 'The handshake has already finished.')
      end

      # A caller that does not need to tell the four apart can rescue the one parent class.
      it 'raises subclasses of NoiseHandshakeError' do
        expect { initiator.write_message('') }.to raise_error(Noise::Exceptions::NoiseHandshakeError)
        expect { initiator.encrypt('') }.to raise_error(Noise::Exceptions::NoiseHandshakeError)
      end
    end

    describe 'a handshake message that fails to decrypt' do
      let(:name) { 'Noise_NNpsk0_25519_AESGCM_SHA256' }

      before do
        initiator.psks = [('00' * 32).htb]
        responder.psks = [('11' * 32).htb]
        initiator.start_handshake
        responder.start_handshake
      end

      # The turn passes before the message is decrypted, so the reader is left ready to write the
      # fallback handshake message. #fallback depends on this.
      it 'leaves the reader on the turn it moved to' do
        expect { responder.read_message(initiator.write_message('')) }
          .to raise_error(Noise::Exceptions::DecryptError)

        expect(responder.state).to eq :handshake_write
      end
    end

    describe '#fallback' do
      let(:name) { 'Noise_XX_25519_AESGCM_SHA256' }
      let(:initiator) { Noise::Connection::Initiator.new(name, keypairs: { s: ('11' * 32).htb }) }
      let(:responder) { Noise::Connection::Responder.new(name, keypairs: { s: ('22' * 32).htb }) }

      before do
        initiator.start_handshake
        responder.start_handshake
        responder.read_message(initiator.write_message(''))
      end

      # The roles swap, so the party that wrote the aborted message reads the fallback one, and
      # the party that could not read it writes.
      it 'keeps the turn each party is already on' do
        initiator.fallback('Noise_XXfallback_25519_AESGCM_SHA256')
        responder.fallback('Noise_XXfallback_25519_AESGCM_SHA256')

        expect(initiator.state).to eq :handshake_read
        expect(responder.state).to eq :handshake_write
      end

      it 'leaves the running handshake untouched when the fallback name is invalid' do
        expect { initiator.fallback('Noise_NOSUCHPATTERN_25519_AESGCM_SHA256') }
          .to raise_error(Noise::Exceptions::ProtocolNameError)

        expect(initiator.state).to eq :handshake_read
        expect(initiator.protocol.name).to eq name
      end
    end
  end
end
