# frozen_string_literal: true

module Noise
  module State
    # A HandshakeState object contains a SymmetricState plus the following variables, any of which may be empty. Empty
    # is a special value which indicates the variable has not yet been initialized.
    #
    # s: The local static key pair
    # e: The local ephemeral key pair
    # rs: The remote party's static public key
    # re: The remote party's ephemeral public key
    #
    # A HandshakeState also has variables to track its role, and the remaining portion of the handshake pattern:
    #
    # initiator: A boolean indicating the initiator or responder role.
    #
    # message_patterns: A sequence of message patterns.
    #     Each message pattern is a sequence of tokens from the set ("e", "s", "ee", "es", "se", "ss").
    class HandshakeState
      attr_reader :message_patterns, :symmetric_state
      attr_reader :s, :rs, :e, :re

      def initialize(connection, initiator, prologue, local_keypairs, remote_keys)
        @connection = connection
        @protocol = connection.protocol
        @symmetric_state = SymmetricState.initialize_symmetric(@protocol, connection, prologue: prologue)
        @initiator = initiator
        @s = local_keypairs[:s]
        @e = local_keypairs[:e]
        @rs = remote_keys[:rs]
        @re = remote_keys[:re]

        initiator_keypair_getter, responder_keypair_getter = get_keypair_getter(initiator)

        # Sets message_patterns to the message patterns from handshake_pattern
        @message_patterns = @protocol.pattern.tokens.dup

        process_initiator_pre_messages(initiator_keypair_getter)
        process_fallback(initiator_keypair_getter)
        process_responder_pre_messages(responder_keypair_getter)
      end

      def get_keypair_getter(initiator)
        if initiator
          [local_keypair_getter, remote_keypair_getter]
        else
          [remote_keypair_getter, local_keypair_getter]
        end
      end

      def local_keypair_getter
        ->(token) { instance_variable_get('@' + token.to_s).public_key }
      end

      def remote_keypair_getter
        ->(token) { instance_variable_get('@r' + token.to_s) }
      end

      def process_initiator_pre_messages(keypair_getter)
        @protocol.pattern.initiator_pre_messages&.map do |token|
          keypair = keypair_getter.call(token)
          @symmetric_state.mix_hash(keypair)
        end
      end

      def process_fallback(initiator_keypair_getter)
        return unless @protocol.pattern.fallback

        message = @message_patterns.delete_at(0).first
        public_key = initiator_keypair_getter.call(message)
        @symmetric_state.mix_hash(public_key)
      end

      def process_responder_pre_messages(keypair_getter)
        @protocol.pattern.responder_pre_messages&.map do |token|
          keypair = keypair_getter.call(token)
          @symmetric_state.mix_hash(keypair)
        end
      end

      def expected_message_length(payload_size)
        has_key = @symmetric_state.cipher_state.key?
        pattern = @message_patterns.first
        len = pattern.inject(0) do |l, token|
          case token
          when Noise::Token::E
            l += @protocol.dh_fn.dhlen
            has_key = true if @protocol.psk?
          when Noise::Token::S
            l += @protocol.dh_fn.dhlen
            l += 16 if has_key
          else
            has_key = true
          end
          l
        end
        len += payload_size
        len += 16 if has_key
        len
      end

      # Takes a payload byte sequence which may be zero-length, and a message_buffer to write the output into
      def write_message(payload, message_buffer)
        pattern = @message_patterns.shift

        pattern.each do |token|
          case token
          when Noise::Token::E
            @e ||= dh_fn.generate_keypair
            message_buffer << @e.public_key
            mix_e(@e.public_key)
          when Noise::Token::S
            message_buffer << @symmetric_state.encrypt_and_hash(@s.public_key)
          when Noise::Token::EE, Noise::Token::ES, Noise::Token::SE, Noise::Token::SS
            token.mix(@symmetric_state, @protocol.dh_fn, @initiator, self)
          when Noise::Token::PSK
            mix_psk
          when Noise::Token::E1
            keypair ||= @protocol.hybrid_fn.generate_kem_keypair
            message_buffer << @symmetric_state.encrypt_and_hash(keypair.public_key)
          when Noise::Token::EKEM1
            ciphertext, kem_output = @protocol.hybrid_fn.generate_kem_ciphertext(@rs)
            message_buffer << @symmetric_state.encrypt_and_hash(ciphertext)
            @symmetric_state.mix_key(kem_output)

            # private_key, public_key = get_key(keypair, initiator)
            # symmetric_state.mix_key(dh_fn.dh(private_key, public_key))
          end
        end
        message_buffer << @symmetric_state.encrypt_and_hash(payload)
        @symmetric_state.split if @message_patterns.empty?
      end

      # Takes a byte sequence containing a Noise handshake message,
      # and a payload_buffer to write the message's plaintext payload into
      def read_message(message, payload_buffer)
        pattern = @message_patterns.shift
        pattern.each do |token|
          case token
          when Noise::Token::E
            message, re = extract_key(message, false)
            @re ||= re
            mix_e(@re)
          when Noise::Token::S
            message, @rs = extract_key(message, true)
          when Noise::Token::EE, Noise::Token::ES, Noise::Token::SE, Noise::Token::SS
            token.mix(@symmetric_state, @protocol.dh_fn, @initiator, self)
          when Noise::Token::PSK
            mix_psk
          when Noise::Token::E1
            Noise.logger.warn("Invalid token")
          when Noise::Token::EKEM1
            kem_output = @protocol.hybrid_fn.kem(@e, message)
            @symmetric_state.mix_key(kem_output)
          end
        end
        payload_buffer << @symmetric_state.decrypt_and_hash(message)
        @symmetric_state.split if @message_patterns.empty?
      end

      private

      def extract_key(message, is_encrypted)
        len = @protocol.dh_fn.dhlen
        offset =
          if is_encrypted && @connection.cipher_state_handshake.key?
            16
          else
            0
          end
        key = message[0...len + offset]
        message = message[(len + offset)..-1]
        key = @symmetric_state.decrypt_and_hash(key) if is_encrypted
        [message, key]
      end

      def mix_e(public_key)
        @symmetric_state.mix_hash(public_key)
        @symmetric_state.mix_key(public_key) if @protocol.psk?
      end

      def mix_psk
        @symmetric_state.mix_key_and_hash(@connection.psks.shift)
      end
    end
  end
end
