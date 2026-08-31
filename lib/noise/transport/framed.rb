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
      # @param [IO] io the stream to read from and write to. Anything that answers #write and
      #   #readpartial will do, which is what makes a StringIO usable in a test.
      # @param [Numeric, nil] read_timeout how long #read waits for the next bytes of a frame
      #   before giving up, in seconds. nil waits as long as the IO does. It applies to each wait
      #   for more bytes rather than to the frame as a whole, so a peer that sends a byte at a
      #   time holds the read open indefinitely without ever tripping it.
      # @raise [Noise::Exceptions::HandshakeNotFinishedError] if the handshake has not finished.
      # @raise [ArgumentError] if read_timeout is negative, or if the IO cannot be waited on and
      #   the timeout would therefore do nothing.
      def initialize(connection, io, read_timeout: nil)
        unless connection.handshake_finished?
          raise Noise::Exceptions::HandshakeNotFinishedError, 'The handshake has not finished.'
        end

        validate_read_timeout!(io, read_timeout)
        @connection = connection
        @io = io
        @read_timeout = read_timeout
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

        write_fully([ciphertext.bytesize].pack('n') + ciphertext)
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
        prefix = read_exactly(LENGTH_PREFIX_LENGTH, allow_eof: true)
        return nil if prefix.nil?

        @connection.decrypt(read_exactly(prefix.unpack1('n')))
      end

      private

      # An IO may take fewer bytes than it is handed, so this keeps offering the rest.
      #
      # @param [String] frame the bytes to write.
      # @raise [IOError] if a write takes none of them, which would otherwise spin here forever.
      # @return [Integer] frame.bytesize, once all of it has gone out.
      def write_fully(frame)
        written = 0
        while written < frame.bytesize
          taken = @io.write(frame.byteslice(written, frame.bytesize - written))
          raise IOError, "#{@io.class} took #{taken.inspect} of the #{frame.bytesize} bytes it was given." unless
            taken.is_a?(Integer) && taken.positive?

          written += taken
        end
        written
      end

      # @param [IO] io the stream the transport was given.
      # @param [Numeric, nil] read_timeout the timeout it was given.
      # @raise [ArgumentError] if the timeout could not be honoured as asked.
      # @return [void]
      def validate_read_timeout!(io, read_timeout)
        return if read_timeout.nil?

        raise ArgumentError, "read_timeout is #{read_timeout}, which is not a length of time." if read_timeout.negative?
        return if io.respond_to?(:wait_readable)

        raise ArgumentError,
              "read_timeout cannot be honoured on a #{io.class}, which does not answer #wait_readable. " \
              'Leave it out, or pass an IO that does.'
      end

      # @param [Integer] length how many bytes to read.
      # @param [Boolean] allow_eof whether a stream that ends before the first of them is an
      #   ending rather than a truncation.
      # @raise [Noise::Exceptions::TruncatedMessageError] if the stream ends after some of them.
      # @return [String, nil] exactly length bytes, or nil for the ending allow_eof permits.
      def read_exactly(length, allow_eof: false)
        # Binary, because a frame is bytes: appending a chunk to a buffer of another encoding
        # would count characters where this counts bytes.
        buffer = ''.b
        while buffer.bytesize < length
          chunk = read_chunk(length - buffer.bytesize)
          if chunk.nil?
            return nil if allow_eof && buffer.empty?

            raise Noise::Exceptions::TruncatedMessageError,
                  "Needed #{length} bytes, the stream ended after #{buffer.bytesize}."
          end
          buffer << chunk
        end
        buffer
      end

      # Takes whatever has arrived, which on a socket is rarely the whole frame at once.
      #
      # @param [Integer] length the most to take.
      # @return [String, nil] the bytes, or nil at end of stream.
      def read_chunk(length)
        wait_readable
        @io.readpartial(length)
      rescue EOFError
        nil
      end

      # Asks the IO itself to wait, rather than selecting on its file descriptor, because bytes it
      # has already read and buffered are ready to be taken while the descriptor is quiet.
      #
      # @raise [Noise::Exceptions::ReadTimeoutError] if nothing arrives within read_timeout.
      # @return [void]
      def wait_readable
        return if @read_timeout.nil?
        return if @io.wait_readable(@read_timeout)

        raise Noise::Exceptions::ReadTimeoutError,
              "No more of the frame arrived within #{@read_timeout} seconds."
      end
    end
  end
end
