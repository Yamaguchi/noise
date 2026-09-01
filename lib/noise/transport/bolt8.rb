# frozen_string_literal: true

module Noise
  module Transport
    # The BOLT #8 transport layer, which turns the message-oriented Noise::Connection into the
    # byte stream the Lightning Network sends over TCP.
    #
    # A Lightning message goes out as two Noise messages: the length of the payload as a two-byte
    # big-endian integer, encrypted on its own, and then the payload. The receiver decrypts the
    # first to learn how many bytes to read for the second. Each direction rotates its key on a
    # schedule of its own, so that a key stolen later cannot decrypt what came before it.
    #
    # Run the handshake with Noise::Connection first, and wrap the finished connection:
    #
    #   connection = Noise::Connection::Initiator.new(Noise::Transport::Bolt8::PROTOCOL_NAME,
    #                                                 keypairs: { s: local_static, rs: node_id })
    #   connection.prologue = Noise::Transport::Bolt8::PROLOGUE
    #   connection.start_handshake
    #   # ... exchange the three handshake messages over the socket ...
    #   transport = Noise::Transport::Bolt8.new(connection, socket)
    #
    #   transport.write('a lightning message')
    #   message = transport.read
    #
    # The transport takes over the connection's transport phase: it holds the very CipherStates
    # the connection does, so once one is wrapped, stop calling the connection's #encrypt,
    # #decrypt, nonce accessors and rekey methods. Every one of them moves the same key and nonce,
    # and the peer has no way to learn that they did.
    #
    # One transport belongs to one thread, for the reason Noise::Connection::Base gives.
    class Bolt8
      # BOLT #8 fixes the handshake to this protocol, and this prologue.
      PROTOCOL_NAME = 'Noise_XK_secp256k1_ChaChaPoly_SHA256'
      PROLOGUE = 'lightning'

      # The payload length goes out as a two-byte big-endian integer, so the header is those two
      # bytes plus the authentication tag over them.
      LENGTH_PREFIX_LENGTH = 2
      HEADER_LENGTH = LENGTH_PREFIX_LENGTH + Noise::State::CipherState::TAG_LENGTH

      # What two bytes of length can express, and what BOLT #8 allows a Lightning message to be.
      # Its authentication tag brings such a message to 65551 bytes, past the 65535 a single Noise
      # transport message may be, so Noise::Connection#encrypt would refuse the largest messages
      # the Lightning Network permits. That is why this class encrypts through the CipherState.
      MAX_PAYLOAD_LENGTH = 65_535

      # @param [Noise::Connection::Base] connection a finished BOLT #8 handshake.
      # @param [IO] io the stream to read from and write to. See Noise::Transport::Stream.
      # @param [Numeric, nil] read_timeout how long #read waits for the next bytes of a message
      #   before giving up, in seconds. See Noise::Transport::Stream.
      # @raise [Noise::Exceptions::HandshakeNotFinishedError] if the handshake has not finished.
      # @raise [Noise::Exceptions::ProtocolNameError] if the connection runs another protocol.
      # @raise [Noise::Exceptions::NoiseValidationError] if the connection is half-duplex.
      # @raise [ArgumentError] if read_timeout is negative, or if the IO cannot be waited on.
      def initialize(connection, io, read_timeout: nil)
        validate(connection)

        @stream = Stream.new(io, read_timeout: read_timeout)
        hkdf_fn = connection.protocol.hkdf_fn
        # Both directions start from the chaining key the handshake ended with, and rotate away
        # from it independently.
        @send = Direction.new(connection.cipher_state_encrypt, connection.chaining_key, hkdf_fn)
        @receive = Direction.new(connection.cipher_state_decrypt, connection.chaining_key, hkdf_fn)
      end

      # Encrypts one Lightning message and writes it to the IO: the encrypted length, then the
      # encrypted payload. It returns once all of it has gone out.
      #
      # @param [String] payload the message, at most MAX_PAYLOAD_LENGTH bytes.
      # @raise [Noise::Exceptions::MessageTooLongError] if the payload is longer than that.
      # @raise [IOError] if the IO accepts none of the bytes it is handed.
      # @return [Integer] how many bytes were written.
      def write(payload)
        if payload.bytesize > MAX_PAYLOAD_LENGTH
          raise Noise::Exceptions::MessageTooLongError,
                "Message is #{payload.bytesize} bytes, which exceeds the maximum of #{MAX_PAYLOAD_LENGTH}."
        end

        @stream.write(@send.encrypt([payload.bytesize].pack('n')) + @send.encrypt(payload))
      end

      # Reads one Lightning message, blocking until all of it has arrived.
      #
      # Every failure ends the transport. BOLT #8 requires the connection to be closed on a
      # decryption failure, and a message that stops part way through leaves the stream in the
      # middle of one, where the next read would take a payload for a length.
      #
      # An error the IO itself raises, such as Errno::ECONNRESET, comes through as it is.
      #
      # @raise [Noise::Exceptions::TruncatedMessageError] if the stream ends part way through a
      #   message.
      # @raise [Noise::Exceptions::ReadTimeoutError] if no more bytes arrive in time.
      # @raise [Noise::Exceptions::DecryptError] if either half fails to authenticate.
      # @return [String, nil] the payload, or nil if the stream ended between messages.
      def read
        header = @stream.read_exactly_or_nil(HEADER_LENGTH)
        return nil if header.nil?

        length = @receive.decrypt(header).unpack1('n')
        @receive.decrypt(@stream.read_exactly(length + Noise::State::CipherState::TAG_LENGTH))
      end

      private

      # BOLT #8 gives each direction a key, a nonce and a chaining key of its own, so a half-duplex
      # connection, which shares one CipherState both ways, cannot carry it. Two Directions over
      # one CipherState would advance a single nonce on both sending and receiving, and rotate to
      # two different chaining keys, which no BOLT #8 peer would follow. Two such parties still
      # talk to each other, so nothing but this check would report it.
      #
      # @param [Noise::Connection::Base] connection the connection to wrap.
      # @return [void]
      def validate(connection)
        unless connection.handshake_finished?
          raise Noise::Exceptions::HandshakeNotFinishedError, 'The handshake has not finished.'
        end

        unless connection.protocol.name == PROTOCOL_NAME
          raise Noise::Exceptions::ProtocolNameError,
                "BOLT #8 runs #{PROTOCOL_NAME}, not #{connection.protocol.name}."
        end

        return unless connection.half_duplex?

        raise Noise::Exceptions::NoiseValidationError,
              'BOLT #8 gives each direction a key of its own, so it cannot run half-duplex.'
      end

      # One direction of the transport: the key it encrypts or decrypts with, and the chaining key
      # the next one is derived from. BOLT #8 calls these sk and sck for sending, rk and rck for
      # receiving, and rotates each direction on its own count.
      class Direction
        # BOLT #8 rotates a key once the nonce dedicated to it reaches 1000. A Lightning message
        # is encrypted twice, once for its length and once for its payload, so that is every 500
        # messages.
        KEY_ROTATION_NONCE = 1000

        # @param [Noise::State::CipherState] cipher_state the transport CipherState Split() gave
        #   this direction.
        # @param [String] chaining_key the chaining key the handshake ended with.
        # @param [Proc] hkdf_fn the protocol's HKDF.
        def initialize(cipher_state, chaining_key, hkdf_fn)
          @cipher_state = cipher_state
          @chaining_key = chaining_key
          @hkdf_fn = hkdf_fn
        end

        # @param [String] plaintext
        # @return [String] the ciphertext and its authentication tag.
        def encrypt(plaintext)
          @cipher_state.encrypt_with_ad('', plaintext).tap { rotate_key_if_due }
        end

        # @param [String] ciphertext
        # @raise [Noise::Exceptions::DecryptError] if it fails to authenticate, in which case the
        #   key is not rotated and the nonce does not move.
        # @return [String] the plaintext.
        def decrypt(ciphertext)
          @cipher_state.decrypt_with_ad('', ciphertext).tap { rotate_key_if_due }
        end

        private

        # Replaces this direction's key with HKDF(ck, k), which also restarts the nonce at zero.
        # This is not Noise's REKEY(k): it draws on the chaining key, so a key stolen now says
        # nothing about the keys the direction used before it.
        #
        # @return [void]
        def rotate_key_if_due
          # Every message through this class advances the nonce by one, so the test could be an
          # equality. It is not, so that a nonce moved from outside cannot carry the direction
          # past the point it rotates at and leave it on one key for good.
          return unless @cipher_state.n >= KEY_ROTATION_NONCE

          @chaining_key, key = @hkdf_fn.call(@chaining_key, @cipher_state.k, 2)
          @cipher_state.initialize_key(key)
          nil
        end
      end
      private_constant :Direction
    end
  end
end
