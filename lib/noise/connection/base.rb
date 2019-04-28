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

        @keypairs = keypairs
        # parameter keypairs[:e] and keypairs[:s] are strings, so should convert Noise::Key object.
        @keypairs[:e] = @protocol.dh_fn.class.from_private(@keypairs[:e]) if @keypairs[:e]
        @keypairs[:s] = @protocol.dh_fn.class.from_private(@keypairs[:s]) if @keypairs[:s]

        @handshake_started = false
        @handshake_finished = false
        @next_message = nil
      end

      def start_handshake
        validate
        initialise_handshake_state
        @handshake_started = true
      end

      def initialise_handshake_state
        @handshake_state = Noise::State::HandshakeState.new(
          self,
          protocol,
          initiator?,
          @prologue,
          @keypairs
        )
        @symmetric_state = @handshake_state.symmetric_state
        @cipher_state_handshake = @symmetric_state.cipher_state
      end

      def write_message(payload = '')
        # Call NoiseConnection.start_handshake first
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_started
        raise Noise::Exceptions::NoiseHandshakeError if @next_message != :write
        # Handshake finished. NoiseConnection.encrypt should be used now
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
        # Handshake finished. NoiseConnection.encrypt should be used now
        raise Noise::Exceptions::NoiseHandshakeError if @handshake_finished

        @next_message = :write
        buffer = +''
        result = @handshake_state.read_message(data, buffer)
        @handshake_finished = true if result
        buffer
      end

      def encrypt(data)
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_finished
        # raise Noise::Exceptions::NoiseInvalidMessage
        @cipher_state_encrypt.encrypt_with_ad('', data)
      end

      def decrypt(data)
        raise Noise::Exceptions::NoiseHandshakeError unless @handshake_finished
        # raise Noise::Exceptions::NoiseInvalidMessage
        @cipher_state_decrypt.decrypt_with_ad('', data)
      end

      def validate_psk!
        # Invalid psk length! Has to be 32 bytes long
        raise Noise::Exceptions::NoisePSKError if @psks.any? { |psk| psk.bytesize != 32 }
        # Bad number of PSKs provided to this protocol! {} are required,
        # given {}'.format(self.pattern.psk_count, len(self.psks)))
        raise Noise::Exceptions::NoisePSKError if @protocol.pattern.psk_count != @psks.count
      end

      def valid_keypairs?
        @protocol.pattern.required_keypairs(initiator?).any? { |keypair| !@keypairs[keypair] }
      end

      def validate
        validate_psk! if psk_handshake?

        # 'Keypair {} has to be set for chosen handshake pattern'.format(keypair)
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
