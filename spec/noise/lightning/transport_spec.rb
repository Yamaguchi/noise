# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

using Noise::Utils::HexString

RSpec.describe Noise::Lightning::Transport do
  # The keys of the BOLT #8 handshake test vector, which spec/vectors/lightning.txt also carries.
  let(:initiator_static) { ('11' * 32).htb }
  let(:initiator_ephemeral) { ('12' * 32).htb }
  let(:responder_static) { ('21' * 32).htb }
  let(:responder_ephemeral) { ('22' * 32).htb }
  let(:node_id) { '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7'.htb }

  let(:initiator) do
    Noise::Connection::Initiator.new(
      described_class::PROTOCOL_NAME,
      keypairs: { s: initiator_static, e: initiator_ephemeral, rs: node_id }
    )
  end
  let(:responder) do
    Noise::Connection::Responder.new(
      described_class::PROTOCOL_NAME,
      keypairs: { s: responder_static, e: responder_ephemeral }
    )
  end

  before do
    [initiator, responder].each do |connection|
      connection.prologue = described_class::PROLOGUE
      connection.start_handshake
    end
    responder.read_message(initiator.write_message(''))
    initiator.read_message(responder.write_message(''))
    responder.read_message(initiator.write_message(''))
  end

  describe '.new' do
    it 'refuses a handshake that has not finished' do
      fresh = Noise::Connection::Initiator.new(described_class::PROTOCOL_NAME, keypairs: { rs: node_id })

      expect { described_class.new(fresh) }
        .to raise_error(Noise::Exceptions::HandshakeNotFinishedError, 'The handshake has not finished.')
    end

    it 'refuses a half-duplex connection, which has one key for both directions' do
      half = Noise::Connection::Initiator.new(
        described_class::PROTOCOL_NAME,
        keypairs: { s: initiator_static, e: initiator_ephemeral, rs: node_id }, half_duplex: true
      )
      peer = Noise::Connection::Responder.new(
        described_class::PROTOCOL_NAME,
        keypairs: { s: responder_static, e: responder_ephemeral }, half_duplex: true
      )
      [half, peer].each do |connection|
        connection.prologue = described_class::PROLOGUE
        connection.start_handshake
      end
      peer.read_message(half.write_message(''))
      half.read_message(peer.write_message(''))
      peer.read_message(half.write_message(''))

      expect { described_class.new(half) }
        .to raise_error(Noise::Exceptions::NoiseValidationError,
                        'BOLT #8 gives each direction a key of its own, so it cannot run half-duplex.')
    end

    it 'refuses a connection running another protocol' do
      other = Noise::Connection::Initiator.new('Noise_NN_25519_AESGCM_SHA256')
      other.start_handshake
      responder_nn = Noise::Connection::Responder.new('Noise_NN_25519_AESGCM_SHA256')
      responder_nn.start_handshake
      responder_nn.read_message(other.write_message(''))
      other.read_message(responder_nn.write_message(''))

      expect { described_class.new(other) }
        .to raise_error(Noise::Exceptions::ProtocolNameError, /BOLT #8 runs #{described_class::PROTOCOL_NAME}/)
    end
  end

  describe 'the handshake this builds on' do
    it 'ends on the chaining key the BOLT #8 test vector gives' do
      expect(initiator.chaining_key.bth)
        .to eq '919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01'
      expect(responder.chaining_key).to eq initiator.chaining_key
    end

    it 'ends on the sending and receiving keys the BOLT #8 test vector gives' do
      expect(initiator.cipher_state_encrypt.k.bth)
        .to eq '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9'
      expect(initiator.cipher_state_decrypt.k.bth)
        .to eq 'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442'
    end
  end

  describe '#write and #read' do
    subject(:transport) { described_class.new(initiator) }

    let(:peer) { described_class.new(responder) }

    it 'frames a message as an encrypted length and an encrypted payload' do
      frame = transport.write('hello')

      expect(frame.bytesize).to eq described_class::HEADER_LENGTH + 5 + 16
      expect(peer.read(StringIO.new(frame))).to eq 'hello'
    end

    it 'round trips a zero length payload' do
      expect(peer.read(StringIO.new(transport.write('')))).to eq ''
    end

    it 'round trips the longest payload BOLT #8 allows' do
      payload = 'a' * described_class::MAX_PAYLOAD_LENGTH

      expect(peer.read(StringIO.new(transport.write(payload)))).to eq payload
    end

    it 'refuses a payload longer than that' do
      expect { transport.write('a' * (described_class::MAX_PAYLOAD_LENGTH + 1)) }
        .to raise_error(Noise::Exceptions::MessageTooLongError, /65536 bytes.*maximum of 65535/)
    end

    it 'reads one message at a time out of a stream that holds several' do
      stream = StringIO.new(transport.write('one') + transport.write('two') + transport.write('three'))

      expect(peer.read(stream)).to eq 'one'
      expect(peer.read(stream)).to eq 'two'
      expect(peer.read(stream)).to eq 'three'
    end

    it 'reports a stream that ends inside the header' do
      expect { peer.read(StringIO.new(transport.write('hello')[0, 10])) }
        .to raise_error(Noise::Exceptions::TruncatedMessageError, 'Needed 18 bytes, the stream ended after 10.')
    end

    it 'reports a stream that ends inside the payload' do
      expect { peer.read(StringIO.new(transport.write('hello')[0, 20])) }
        .to raise_error(Noise::Exceptions::TruncatedMessageError, 'Needed 21 bytes, the stream ended after 2.')
    end

    it 'reports a header that fails to authenticate' do
      frame = transport.write('hello')
      frame[0] = (frame[0].ord ^ 0xff).chr

      expect { peer.read(StringIO.new(frame)) }.to raise_error(Noise::Exceptions::DecryptError)
    end

    it 'reports a payload that fails to authenticate' do
      frame = transport.write('hello')
      tampered = described_class::HEADER_LENGTH
      frame[tampered] = (frame[tampered].ord ^ 0xff).chr

      expect { peer.read(StringIO.new(frame)) }.to raise_error(Noise::Exceptions::DecryptError)
    end

    it 'works in both directions' do
      expect(peer.read(StringIO.new(transport.write('to the responder')))).to eq 'to the responder'
      expect(transport.read(StringIO.new(peer.write('to the initiator')))).to eq 'to the initiator'
    end
  end

  # The message encryption test vectors of BOLT #8: the initiator sends "hello" 1001 times, and
  # each direction rotates its key once its nonce reaches 1000, which is every 500 messages.
  #
  # https://github.com/lightning/bolts/blob/master/08-transport.md
  describe 'key rotation' do
    subject(:transport) { described_class.new(initiator) }

    let(:peer) { described_class.new(responder) }
    let(:expected) do
      {
        0 => 'cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95',
        1 => '72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1',
        500 => '178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8',
        501 => '1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd',
        1000 => '4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09',
        1001 => '2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36'
      }
    end

    it 'matches the BOLT #8 message encryption test vectors' do
      produced = {}
      0.upto(1001) do |index|
        frame = transport.write('hello')
        produced[index] = frame.bth if expected.key?(index)
        expect(peer.read(StringIO.new(frame))).to eq 'hello'
      end

      expect(produced).to eq expected
    end
  end
end
