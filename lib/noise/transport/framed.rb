# frozen_string_literal: true

module Noise
  module Transport
    # A Noise connection framed for a byte stream: every message goes out preceded by its length,
    # so that the reader knows how many bytes to take before decrypting.
    #
    #   transport = Noise::Transport::Framed.new(connection, socket)
    #   transport.write('a message')
    #   message = transport.read
    #
    # The connection learns nothing about the IO, and this class learns nothing about the
    # handshake: it takes one that has already finished.
    #
    # The length goes out in the clear, as two big-endian bytes. It is not secret in any useful
    # sense — anyone watching the stream can time the bytes and count them either way — but it does
    # mean this framing hides nothing about how long each message is. A protocol that has to hide
    # its message sizes pads them, or encrypts the length as BOLT #8 does.
    #
    # Two bytes are enough because a Noise transport message may not exceed 65535 bytes, so a
    # length this can express is never one the connection would refuse. The payload limit is lower
    # by the authentication tag, and Noise::Connection#encrypt is what enforces it.
    #
    # This class holds the connection's transport phase, so once a connection is framed, stop
    # calling its #encrypt and #decrypt directly: a message that goes out unframed leaves the
    # reader taking the next message's bytes for a length. One transport belongs to one thread,
    # for the reason Noise::Connection::Base gives.
    class Framed
      # The length prefix, as two big-endian bytes.
      LENGTH_PREFIX_LENGTH = 2

      # The longest payload #write takes, which is a Noise transport message less its tag. Two
      # bytes of length cannot announce more than the 65535 a transport message may be, so a
      # declared length is never one the connection would refuse.
      MAX_PAYLOAD_LENGTH = Noise::Connection::Base::MAX_PLAINTEXT_LENGTH

      # @param [Noise::Connection::Base] connection a connection whose handshake has finished.
      # @param [IO] io the stream to read from and write to. See Noise::Transport::Stream.
      # @param [Numeric, nil] read_timeout how long #read waits for the next bytes of a frame
      #   before giving up, in seconds. See Noise::Transport::Stream.
      # @raise [Noise::Exceptions::HandshakeNotFinishedError] if the handshake has not finished.
      # @raise [ArgumentError] if read_timeout is negative, or if the IO cannot be waited on and
      #   the timeout would therefore do nothing.
      def initialize(connection, io, read_timeout: nil)
        unless connection.handshake_finished?
          raise Noise::Exceptions::HandshakeNotFinishedError, 'The handshake has not finished.'
        end

        @connection = connection
        @stream = Stream.new(io, read_timeout: read_timeout)
      end

      # Encrypts one message and writes it to the IO, preceded by its length. It returns once the
      # whole frame has been written, however many writes that takes.
      #
      # An error the IO itself raises, such as Errno::EPIPE when the peer has gone, comes through
      # as it is.
      #
      # @param [String] payload at most MAX_PAYLOAD_LENGTH bytes.
      # @raise [Noise::Exceptions::MessageTooLongError] if the payload is longer than that.
      # @raise [IOError] if the IO accepts none of the bytes it is handed, which no IO that keeps
      #   its side of the bargain does.
      # @return [Integer] how many bytes were written, the payload plus its tag and its length.
      def write(payload)
        ciphertext = @connection.encrypt(payload)

        @stream.write([ciphertext.bytesize].pack('n') + ciphertext)
      end

      # Reads one message, waiting until all of it has arrived.
      #
      # Every failure ends the transport, for a different reason each time. A DecryptError says
      # the frame was not written by the party this connection shares a key with, or not written
      # in the order it claims; the stream is still at a frame boundary and the nonce has not
      # moved, so reading on is possible, but reading on from a peer that just failed to
      # authenticate is not something to do. A TruncatedMessageError or a ReadTimeoutError leaves
      # the bytes already taken out of the stream and nowhere to put them, so the next read would
      # take the middle of a frame for a length. Build a new connection instead.
      #
      # An error the IO itself raises, such as Errno::ECONNRESET when the peer disappears without
      # closing, comes through as it is rather than as one of these.
      #
      # @raise [Noise::Exceptions::TruncatedMessageError] if the stream ends part way through a
      #   frame.
      # @raise [Noise::Exceptions::ReadTimeoutError] if no more bytes arrive in time.
      # @raise [Noise::Exceptions::DecryptError] if the frame fails to authenticate, which is also
      #   how a length too short to hold an authentication tag is reported.
      # @return [String, nil] the payload, or nil if the stream ended between frames, which is how
      #   the other party closes without cutting a message in half.
      def read
        prefix = @stream.read_exactly_or_nil(LENGTH_PREFIX_LENGTH)
        return nil if prefix.nil?

        @connection.decrypt(@stream.read_exactly(prefix.unpack1('n')))
      end
    end
  end
end
