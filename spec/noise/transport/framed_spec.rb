# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

RSpec.describe Noise::Transport::Framed do
  let(:name) { 'Noise_NN_25519_ChaChaPoly_SHA256' }
  let(:initiator) { Noise::Connection::Initiator.new(name) }
  let(:responder) { Noise::Connection::Responder.new(name) }

  before do
    initiator.start_handshake
    responder.start_handshake
    responder.read_message(initiator.write_message(''))
    initiator.read_message(responder.write_message(''))
  end

  describe '.new' do
    it 'refuses a handshake that has not finished' do
      expect { described_class.new(Noise::Connection::Initiator.new(name), StringIO.new) }
        .to raise_error(Noise::Exceptions::HandshakeNotFinishedError, 'The handshake has not finished.')
    end

    # What makes a timeout unusable is Noise::Transport::Stream's to say; this only checks that it
    # is asked before the transport is handed back.
    it 'refuses a read timeout the stream cannot honour' do
      expect { described_class.new(initiator, StringIO.new, read_timeout: 1) }
        .to raise_error(ArgumentError, /StringIO, which does not answer #wait_readable/)
    end
  end

  describe '#write' do
    let(:io) { StringIO.new(''.b) }
    let(:transport) { described_class.new(initiator, io) }

    it 'writes the length of the encrypted message, then the message' do
      written = transport.write('hello')

      expect(written).to eq described_class::LENGTH_PREFIX_LENGTH + 5 + 16
      expect(io.string[0, 2].unpack1('n')).to eq 5 + 16
      expect(io.string.bytesize).to eq written
    end

    it 'refuses a payload longer than a Noise message can carry' do
      expect { transport.write('a' * (described_class::MAX_PAYLOAD_LENGTH + 1)) }
        .to raise_error(Noise::Exceptions::MessageTooLongError, /65520 bytes.*maximum of 65519/)
    end

    it 'keeps writing until the whole frame has gone out, in the right order' do
      slow = ChunkedIO.new(chunk: 7)

      written = described_class.new(initiator, slow).write('hello')

      expect(slow.written.bytesize).to eq written
      # Reading it back is what catches a write that keeps offering the same bytes.
      expect(described_class.new(responder, StringIO.new(slow.written)).read).to eq 'hello'
    end
  end

  describe '#read' do
    let(:frames) { StringIO.new(''.b) }
    let(:sender) { described_class.new(initiator, frames) }

    def receiver(io = StringIO.new(frames.string))
      described_class.new(responder, io)
    end

    it 'round trips a message' do
      sender.write('hello')

      expect(receiver.read).to eq 'hello'
    end

    it 'round trips a zero length payload' do
      sender.write('')

      expect(receiver.read).to eq ''
    end

    it 'round trips the longest payload a Noise message can carry' do
      payload = 'a' * described_class::MAX_PAYLOAD_LENGTH
      sender.write(payload)

      expect(receiver.read).to eq payload
    end

    it 'reads one message at a time out of a stream that holds several' do
      %w[one two three].each { |message| sender.write(message) }
      peer = receiver

      expect([peer.read, peer.read, peer.read]).to eq %w[one two three]
    end

    it 'answers nil when the stream ends between frames' do
      sender.write('hello')
      peer = receiver

      expect(peer.read).to eq 'hello'
      expect(peer.read).to be_nil
    end

    it 'reassembles a frame that arrives a byte at a time' do
      sender.write('hello')

      expect(receiver(ChunkedIO.new(data: frames.string, chunk: 1)).read).to eq 'hello'
    end

    it 'reports a stream that ends inside the length prefix' do
      sender.write('hello')

      expect { receiver(StringIO.new(frames.string[0, 1])).read }
        .to raise_error(Noise::Exceptions::TruncatedMessageError, 'Needed 2 bytes, the stream ended after 1.')
    end

    it 'reports a stream that ends inside the payload' do
      sender.write('hello')

      expect { receiver(StringIO.new(frames.string[0, 10])).read }
        .to raise_error(Noise::Exceptions::TruncatedMessageError, 'Needed 21 bytes, the stream ended after 8.')
    end

    it 'reports a frame too short to hold an authentication tag' do
      expect { receiver(StringIO.new([15].pack('n') + ('a' * 15))).read }
        .to raise_error(Noise::Exceptions::DecryptError, 'Ciphertext is shorter than the tag.')
    end

    it 'reports a frame that fails to authenticate' do
      sender.write('hello')
      tampered = frames.string.b
      tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(-1) ^ 0xff)

      expect { receiver(StringIO.new(tampered)).read }.to raise_error(Noise::Exceptions::DecryptError)
    end

    # Two bytes cannot announce more than 65535, which is the longest transport message Noise
    # allows, so a declared length is never one the connection would refuse.
    it 'cannot announce a length the connection refuses' do
      expect(Noise::Connection::Base::MAX_MESSAGE_LENGTH).to eq 0xffff
    end
  end

  describe 'read_timeout' do
    it 'gives up when the rest of the frame does not arrive' do
      reader, writer = IO.pipe
      writer.write([100].pack('n'))
      transport = described_class.new(responder, reader, read_timeout: 0.05)

      expect { transport.read }
        .to raise_error(Noise::Exceptions::ReadTimeoutError, 'No more of the frame arrived within 0.05 seconds.')
    ensure
      [reader, writer].each(&:close)
    end

    it 'reads a frame that arrives in time' do
      reader, writer = IO.pipe
      described_class.new(initiator, writer).write('hello')

      expect(described_class.new(responder, reader, read_timeout: 5).read).to eq 'hello'
    ensure
      [reader, writer].each(&:close)
    end

    it 'waits as long as the IO does when no timeout is given' do
      reader, writer = IO.pipe
      described_class.new(initiator, writer).write('hello')
      writer.close

      expect(described_class.new(responder, reader).read).to eq 'hello'
    ensure
      reader.close
    end
  end
end
