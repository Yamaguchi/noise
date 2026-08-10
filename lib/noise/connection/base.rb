# frozen_string_literal: true

module Noise
  module Connection
    class Base
      # The Noise spec caps a handshake or transport message at 65535 bytes. A transport message is
      # the ciphertext, so the plaintext a caller may hand to encrypt is shorter by the
      # authentication tag that ENCRYPT() appends.
      MAX_MESSAGE_LENGTH = 65_535
      MAX_PLAINTEXT_LENGTH = MAX_MESSAGE_LENGTH - Noise::State::CipherState::TAG_LENGTH

      attr_reader :protocol, :handshake_started, :handshake_finished, :handshake_hash, :handshake_state,
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
      def initialize(name, keypairs: { s: nil, e: nil, rs: nil, re: nil })
        @protocol = Protocol.create(name)

        # parameter keypairs[:e] and keypairs[:s] are strings, so should convert Noise::Key object.
        @local_keypairs = {}
        @local_keypairs[:e] = @protocol.dh_fn.class.from_private(keypairs[:e]) if keypairs[:e]
        @local_keypairs[:s] = @protocol.dh_fn.class.from_private(keypairs[:s]) if keypairs[:s]
        @remote_keys = { rs: keypairs[:rs], re: keypairs[:re] }
        @handshake_started = false
        @handshake_finished = false
        initialize_next_message
      end

      def start_handshake
        validate
        initialise_handshake_state
        @handshake_started = true
      end

      # Restarts the handshake with a fallback pattern, carrying over the keys of the aborted one.
      #
      # The roles swap here: the party that wrote the aborted message now reads, and the one that
      # failed to read it now writes. Both sides are already in that state, so @next_message is
      # deliberately left as it is rather than reset through initialize_next_message.
      def fallback(fallback_name)
        @protocol = Protocol.create(fallback_name)
        @handshake_started = false
        @handshake_finished = false
        @local_keypairs = { e: @handshake_state.e, s: @handshake_state.s }
        @remote_keys = { re: @handshake_state.re, rs: @handshake_state.rs }
        start_handshake
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
        # Call NoiseConnection.start_handshake first
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_started
        raise Noise::Exceptions::NoiseHandshakeError if @next_message != :write
        raise Noise::Exceptions::NoiseHandshakeError if @handshake_finished

        length = @handshake_state.expected_message_length(payload.bytesize)
        if length > MAX_MESSAGE_LENGTH
          raise Noise::Exceptions::MessageTooLongError,
                "Message would be #{length} bytes, which exceeds the maximum of #{MAX_MESSAGE_LENGTH}."
        end

        @next_message = :read
        buffer = +''
        @handshake_finished = @handshake_state.write_message(payload, buffer)
        buffer
      end

      def read_message(data)
        # Call NoiseConnection.start_handshake first
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_started
        raise Noise::Exceptions::NoiseHandshakeError if @next_message != :read
        raise Noise::Exceptions::NoiseHandshakeError if @handshake_finished

        if data.bytesize > MAX_MESSAGE_LENGTH
          raise Noise::Exceptions::MessageTooLongError,
                "Message is #{data.bytesize} bytes, which exceeds the maximum of #{MAX_MESSAGE_LENGTH}."
        end

        @next_message = :write
        buffer = +''
        @handshake_finished = @handshake_state.read_message(data, buffer)
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

      # Returns the transport CipherState of the given direction.
      #
      # One-way patterns leave the direction the caller cannot use as nil, so the absence of a
      # cipher state is reported the same way as a handshake that has not finished yet.
      #
      # @param [Symbol] direction :encrypt or :decrypt.
      def transport_cipher_state(direction)
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_finished

        cipher_state = direction == :encrypt ? @cipher_state_encrypt : @cipher_state_decrypt
        raise Noise::Exceptions::NoiseHandshakeError, "This party cannot #{direction} messages." unless cipher_state

        cipher_state
      end
    end
  end
end
