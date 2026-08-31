# frozen_string_literal: true

module Noise
  module Connection
    # A connection moves through four states, and every public operation is legal in some of them
    # and not in others:
    #
    #   :created         -- start_handshake
    #   :handshake_write -- write_message, fallback
    #   :handshake_read  -- read_message, fallback
    #   :transport       -- encrypt, decrypt, rekey_*, the nonce accessors
    #
    # start_handshake moves :created to the state this party starts the pattern in, which is
    # :handshake_write for the initiator and :handshake_read for the responder. Writing or reading
    # a handshake message passes the turn to the other party, and the message that completes the
    # pattern moves the connection to :transport.
    #
    # == Threads
    #
    # One connection belongs to one thread. Nothing here is synchronised: the state above is a
    # plain instance variable, and #encrypt and #decrypt advance the transport nonce with a plain
    # +=, so two threads that share a connection can encrypt two different plaintexts under the
    # same nonce. Neither ChaChaPoly nor AESGCM degrades gracefully when that happens: reusing a
    # nonce breaks the confidentiality of both messages and lets an attacker forge further ones.
    #
    # A caller that has to reach one connection from more than one thread is responsible for
    # serialising every call to it.
    #
    # This class deliberately does not lock. A Mutex would make each call atomic without making
    # concurrent use correct: the transport nonce numbers the messages of a direction, so two
    # threads that both encrypt still hand the transport layer a stream whose order the receiver
    # cannot reconstruct. Only the application knows which message is meant to be first, and once
    # it has said so, its own serialisation has already done what the lock would have done.
    #
    # The other direction is no better. Decrypting a message that arrived out of order is a
    # #decryption_nonce= call followed by a #decrypt call, a sequence no per-call lock can hold
    # together.
    class Base
      # The Noise spec caps a handshake or transport message at 65535 bytes. A transport message is
      # the ciphertext, so the plaintext a caller may hand to encrypt is shorter by the
      # authentication tag that ENCRYPT() appends.
      MAX_MESSAGE_LENGTH = 65_535
      MAX_PLAINTEXT_LENGTH = MAX_MESSAGE_LENGTH - Noise::State::CipherState::TAG_LENGTH

      # The states in which the connection is running a handshake, and what it expects next in
      # each of them. The message explains a HandshakeTurnError.
      TURN_MESSAGES = {
        handshake_write: 'This party writes the next handshake message; it cannot read one yet.',
        handshake_read: 'This party reads the next handshake message; it cannot write one yet.'
      }.freeze
      private_constant :TURN_MESSAGES

      # The states in which a handshake is running, which are the ones #fallback may be called in.
      HANDSHAKE_STATES = TURN_MESSAGES.keys.freeze
      private_constant :HANDSHAKE_STATES

      # @return [Symbol] the current state, one of :created, :handshake_write, :handshake_read and
      #   :transport.
      attr_reader :state

      attr_reader :protocol, :handshake_hash, :handshake_state,
                  :cipher_state_encrypt, :cipher_state_decrypt, :cipher_state_handshake, :s, :rs
      attr_accessor :psks, :prologue

      # @param [String] name the protocol name, for example 'Noise_XX_25519_ChaChaPoly_SHA256'.
      # @param [Hash] keypairs the keys the pattern needs, as private or public key strings.
      #   :s is the local static private key, :rs and :re the remote static and ephemeral public keys.
      #
      #   :e sets the local ephemeral private key. It exists only so that spec/vectors_spec.rb can
      #   reproduce the official test vectors, which fix both sides' ephemeral keys to make the
      #   output deterministic. Never set it outside that use: HandshakeState#write_message reuses
      #   the keypair given here instead of generating a fresh one, and an ephemeral key reused
      #   across handshakes gives up the forward secrecy every pattern depends on. The handshake
      #   still succeeds, so nothing reports the loss.
      # @param [Boolean] half_duplex whether to run the transport phase in half-duplex mode, in
      #   which one CipherState encrypts both directions. See #half_duplex? for what that costs.
      # @raise [Noise::Exceptions::NoiseValidationError] if half_duplex is asked for on a one-way
      #   pattern, which has no messages to alternate.
      def initialize(name, keypairs: { s: nil, e: nil, rs: nil, re: nil }, half_duplex: false)
        @protocol = Protocol.create(name)
        @half_duplex = half_duplex
        validate_half_duplex!

        # parameter keypairs[:e] and keypairs[:s] are strings, so should convert Noise::Key object.
        @local_keypairs = {}
        @local_keypairs[:e] = @protocol.dh_fn.class.from_private(keypairs[:e]) if keypairs[:e]
        @local_keypairs[:s] = @protocol.dh_fn.class.from_private(keypairs[:s]) if keypairs[:s]
        @remote_keys = { rs: keypairs[:rs], re: keypairs[:re] }
        @state = :created
      end

      # Whether the transport phase uses one CipherState for both directions, which is the
      # half-duplex mode of section 11.5 of the Noise specification. Both parties keep the first
      # CipherState that Split() returns and drop the second.
      #
      # It is only safe when the two parties strictly alternate their transport messages. They
      # share one nonce, so if both encrypt before either decrypts, two different plaintexts go
      # out under the same nonce, which breaks the confidentiality of both and lets an attacker
      # forge further ones. Nothing here can check that the application alternates; that is the
      # application protocol's guarantee to make.
      #
      # Because there is one CipherState, the accessors that name a direction all reach it:
      # #encryption_nonce and #decryption_nonce report the same count, setting either sets both,
      # and #rekey_encryption and #rekey_decryption replace the same key.
      #
      # @return [Boolean]
      def half_duplex?
        @half_duplex
      end

      # @return [Boolean] true once #start_handshake has been called.
      def handshake_started?
        @state != :created
      end
      alias handshake_started handshake_started?

      # @return [Boolean] true once the last handshake message has been written or read, which is
      #   when the transport operations become available.
      def handshake_finished?
        @state == :transport
      end
      alias handshake_finished handshake_finished?

      # Starts the handshake this connection was created for. It is legal once: a connection that
      # already has a handshake, running or finished, has keys and a transcript that restarting
      # would silently throw away. #fallback is the supported way to begin a second handshake.
      def start_handshake
        ensure_state!(:created)
        validate
        initialise_handshake_state
        @state = initial_turn
        nil
      end

      # Restarts the handshake with a fallback pattern, carrying over the keys of the aborted one.
      #
      # The roles swap here: the party that wrote the aborted message now reads, and the one that
      # failed to read it now writes. Both sides are already on that turn, so the current turn is
      # carried over rather than reset to the one this party started the aborted pattern on.
      def fallback(fallback_name)
        ensure_state!(*HANDSHAKE_STATES)

        turn = @state
        protocol = Protocol.create(fallback_name)
        validate_half_duplex!(protocol)
        @protocol = protocol
        @local_keypairs = { e: @handshake_state.e, s: @handshake_state.s }
        @remote_keys = { re: @handshake_state.re, rs: @handshake_state.rs }
        # Everything that can fail has run by now, so a bad fallback name leaves the connection on
        # the handshake it was already running. start_handshake accepts a connection in :created
        # alone, so the aborted handshake is cleared here and the turn restored after it.
        @state = :created
        start_handshake
        @state = turn
        nil
      end

      def initialise_handshake_state
        @handshake_state = Noise::State::HandshakeState.new(
          self,
          initiator?,
          @prologue,
          @local_keypairs,
          @remote_keys
        )
        @symmetric_state = @handshake_state.symmetric_state
        @cipher_state_handshake = @symmetric_state.cipher_state
      end

      def write_message(payload = '')
        ensure_state!(:handshake_write)

        length = @handshake_state.expected_message_length(payload.bytesize)
        if length > MAX_MESSAGE_LENGTH
          raise Noise::Exceptions::MessageTooLongError,
                "Message would be #{length} bytes, which exceeds the maximum of #{MAX_MESSAGE_LENGTH}."
        end

        # The turn passes before the message is built, so that a message this party failed to
        # build still leaves the connection waiting for the other party, as fallback expects.
        @state = :handshake_read
        buffer = +''
        @state = :transport if @handshake_state.write_message(payload, buffer)
        buffer
      end

      def read_message(data)
        ensure_state!(:handshake_read)

        if data.bytesize > MAX_MESSAGE_LENGTH
          raise Noise::Exceptions::MessageTooLongError,
                "Message is #{data.bytesize} bytes, which exceeds the maximum of #{MAX_MESSAGE_LENGTH}."
        end

        # See #write_message: the turn passes before the message is read, so that a message that
        # fails to decrypt leaves this party ready to write the fallback handshake message.
        @state = :handshake_write
        buffer = +''
        @state = :transport if @handshake_state.read_message(data, buffer)
        buffer
      end

      def encrypt(data)
        cipher_state = transport_cipher_state(:encrypt)
        if data.bytesize > MAX_PLAINTEXT_LENGTH
          raise Noise::Exceptions::MessageTooLongError,
                "Plaintext is #{data.bytesize} bytes, which exceeds the maximum of #{MAX_PLAINTEXT_LENGTH}."
        end

        cipher_state.encrypt_with_ad('', data)
      end

      def decrypt(data)
        cipher_state = transport_cipher_state(:decrypt)
        # Rejected before the cipher state is used, so an over-long message leaves n untouched
        # and the connection usable, exactly as a failed decryption does.
        if data.bytesize > MAX_MESSAGE_LENGTH
          raise Noise::Exceptions::MessageTooLongError,
                "Message is #{data.bytesize} bytes, which exceeds the maximum of #{MAX_MESSAGE_LENGTH}."
        end

        cipher_state.decrypt_with_ad('', data)
      end

      # @return [Integer] the nonce the next #encrypt call uses.
      def encryption_nonce
        transport_cipher_state(:encrypt).n
      end

      # @return [Integer] the nonce the next #decrypt call uses.
      def decryption_nonce
        transport_cipher_state(:decrypt).n
      end

      # Sets the nonce of the next #encrypt call. Needed when the transport layer numbers the
      # messages itself instead of relying on the sender and the receiver counting in step.
      #
      # @param [Integer] nonce a value between 0 and CipherState::MAX_NONCE.
      def encryption_nonce=(nonce)
        transport_cipher_state(:encrypt).nonce = nonce
      end

      # Sets the nonce of the next #decrypt call. This is how the Noise spec handles transport
      # messages that arrive out of order: the receiver sets n to the nonce of the message it is
      # about to decrypt, and restores the previous value if the message fails to authenticate.
      #
      # @param [Integer] nonce a value between 0 and CipherState::MAX_NONCE.
      def decryption_nonce=(nonce)
        transport_cipher_state(:decrypt).nonce = nonce
      end

      # Replaces the key used by #encrypt with REKEY(k), so that the old key cannot decrypt the
      # messages that follow. Both parties must rekey the matching direction at the same point of
      # the message stream, which is up to the application protocol to agree on.
      #
      # @return [void]
      def rekey_encryption
        transport_cipher_state(:encrypt).rekey
        nil
      end

      # Replaces the key used by #decrypt with REKEY(k). See #rekey_encryption.
      #
      # @return [void]
      def rekey_decryption
        transport_cipher_state(:decrypt).rekey
        nil
      end

      def validate_psk!
        raise Noise::Exceptions::NoisePSKError, 'psks are not set.' if @psks.nil?
        # Invalid psk length! Has to be 32 bytes long
        raise Noise::Exceptions::NoisePSKError, 'psks have to be 32 bytes long.' if
          @psks.any? { |psk| psk.bytesize != 32 }

        return if @protocol.pattern.psk_count == @psks.count

        raise Noise::Exceptions::NoisePSKError,
              "This protocol needs #{@protocol.pattern.psk_count} psks, got #{@psks.count}."
      end

      def missing_keypairs?
        keypairs = @local_keypairs.merge(@remote_keys)
        @protocol.pattern.required_keypairs(initiator?).any? { |keypair| !keypairs[keypair] }
      end

      def validate
        validate_psk! if @protocol.psk?

        raise Noise::Exceptions::NoiseValidationError if missing_keypairs?

        true
      end

      def handshake_done(_c1, _c2)
        @handshake_hash = @symmetric_state.handshake_hash
        @s = @handshake_state.s
        @rs = @handshake_state.rs
        @handshake_state = nil
        @symmetric_state = nil
        @cipher_state_handshake = nil
      end

      private

      # A one-way pattern gives the responder no way to reply, so its parties never alternate and
      # half-duplex has nothing to share a CipherState between. Sharing one anyway would hand the
      # responder an encryption key the pattern is meant to deny it.
      #
      # @param [Noise::Protocol] protocol the protocol to check, which is the one being fallen back
      #   to when #fallback asks.
      # @raise [Noise::Exceptions::NoiseValidationError]
      def validate_half_duplex!(protocol = @protocol)
        return unless @half_duplex && protocol.pattern.one_way?

        raise Noise::Exceptions::NoiseValidationError,
              "#{protocol.name} is a one-way pattern, which cannot run half-duplex."
      end

      # The CipherState for the direction this party did not assign c1 to, which is decryption for
      # the initiator and encryption for the responder.
      #
      # Half-duplex answers c1 both ways, so that the two parties encrypt and decrypt under the
      # same key and nonce as they take turns. A one-way pattern has no second direction at all,
      # so it has none.
      #
      # @param [Noise::State::CipherState] c1 the first CipherState Split() returned.
      # @param [Noise::State::CipherState] c2 the second one.
      # @return [Noise::State::CipherState, nil]
      def other_direction_cipher_state(c1, c2)
        return c1 if half_duplex?

        @protocol.pattern.one_way? ? nil : c2
      end

      # Returns the transport CipherState of the given direction.
      #
      # One-way patterns leave the direction the caller cannot use as nil, so the absence of a
      # cipher state is reported the same way as a handshake that has not finished yet.
      #
      # @param [Symbol] direction :encrypt or :decrypt.
      def transport_cipher_state(direction)
        ensure_state!(:transport)

        cipher_state = direction == :encrypt ? @cipher_state_encrypt : @cipher_state_decrypt
        raise Noise::Exceptions::NoiseHandshakeError, "This party cannot #{direction} messages." unless cipher_state

        cipher_state
      end

      # Raises unless the connection is in one of the states the calling operation is legal in.
      # Every public operation goes through here, so a new one cannot forget its precondition.
      #
      # @param [Array<Symbol>] allowed the states the operation may be called in.
      def ensure_state!(*allowed)
        return if allowed.include?(@state)

        raise state_error(allowed)
      end

      # Builds the exception for an operation called in the wrong state. All four descend from
      # NoiseHandshakeError, so a caller that does not care which one it is can rescue the parent.
      #
      # @param [Array<Symbol>] allowed the states the operation may be called in.
      # @return [Noise::Exceptions::NoiseHandshakeError]
      def state_error(allowed)
        case @state
        when :created
          Noise::Exceptions::HandshakeNotStartedError.new('The handshake has not started. Call #start_handshake.')
        when :transport
          Noise::Exceptions::HandshakeAlreadyFinishedError.new('The handshake has already finished.')
        else
          if allowed.include?(:transport)
            Noise::Exceptions::HandshakeNotFinishedError.new('The handshake has not finished.')
          else
            Noise::Exceptions::HandshakeTurnError.new(TURN_MESSAGES.fetch(@state))
          end
        end
      end
    end
  end
end
