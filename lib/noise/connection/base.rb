# frozen_string_literal: true

module Noise
  module Connection
    class Base
      attr_reader :protocol, :handshake_started, :handshake_finished, :handshake_hash, :handshake_state
      attr_reader :cipher_state_encrypt, :cipher_state_decrypt, :cipher_state_handshake
      attr_accessor :psks, :prologue
      attr_reader :s, :rs

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

      def fallback(fallback_name)
        @protocol = Protocol.create(fallback_name)
        @handshake_started = false
        @handshake_finished = false
        # initialize_next_message
        @local_keypairs = { e: @handshake_state.e, s: @handshake_state.s }
        @remote_keys = { re: @handshake_state.re, rs: @handshake_state.rs }
        start_handshake
      end

      def initialise_handshake_state
        @handshake_state = Noise::State::HandshakeState.new(
          self,
          protocol,
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

        @next_message = :read
        buffer = +''
        result = @handshake_state.write_message(payload, buffer)
        @handshake_finished = true if result
        buffer
      end

      def read_message(data)
        # Call NoiseConnection.start_handshake first
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_started
        raise Noise::Exceptions::NoiseHandshakeError if @next_message != :read
        raise Noise::Exceptions::NoiseHandshakeError if @handshake_finished

        @next_message = :write
        buffer = +''
        result = @handshake_state.read_message(data, buffer)
        @handshake_finished = true if result
        buffer
      end

      def encrypt(data)
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_finished

        @cipher_state_encrypt.encrypt_with_ad('', data)
      end

      def decrypt(data)
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_finished

        @cipher_state_decrypt.decrypt_with_ad('', data)
      end

      def validate_psk!
        # Invalid psk length! Has to be 32 bytes long
        raise Noise::Exceptions::NoisePSKError if @psks.any? { |psk| psk.bytesize != 32 }
        raise Noise::Exceptions::NoisePSKError if @protocol.pattern.psk_count != @psks.count
      end

      def valid_keypairs?
        keypairs = @local_keypairs.merge(@remote_keys)
        @protocol.pattern.required_keypairs(initiator?).any? { |keypair| !keypairs[keypair] }
      end

      def validate
        validate_psk! if psk_handshake?

        raise Noise::Exceptions::NoiseValidationError if valid_keypairs?

        true
      end

      def psk_handshake?
        @protocol.is_psk_handshake
      end

      def handshake_done(_c1, _c2)
        @handshake_hash = @symmetric_state.handshake_hash
        @s = @handshake_state.s
        @rs = @handshake_state.rs
        @handshake_state = nil
        @symmetric_state = nil
        @cipher_state_handshake = nil
      end
    end
  end
end
