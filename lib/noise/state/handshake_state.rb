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

      def initialize(connection, protocol, initiator, prologue, local_keypairs, remote_keys)
        @connection = connection
        @protocol = protocol
        @symmetric_state = SymmetricState.new
        @symmetric_state.initialize_symmetric(@protocol, connection)
        @symmetric_state.mix_hash(prologue)
        @initiator = initiator
        @s = local_keypairs[:s]
        @e = local_keypairs[:e]
        @rs = remote_keys[:rs]
        @re = remote_keys[:re]

        get_local_keypair = ->(token) { instance_variable_get('@' + token).public_key }
        get_remote_keypair = ->(token) { instance_variable_get('@r' + token) }

        if initiator
          initiator_keypair_getter = get_local_keypair
          responder_keypair_getter = get_remote_keypair
        else
          initiator_keypair_getter = get_remote_keypair
          responder_keypair_getter = get_local_keypair
        end

        # Sets message_patterns to the message patterns from handshake_pattern
        @message_patterns = @protocol.pattern.tokens.dup

        @protocol.pattern.initiator_pre_messages&.map do |token|
          keypair = initiator_keypair_getter.call(token)
          @symmetric_state.mix_hash(keypair)
        end

        if @protocol.pattern.fallback
          message = @message_patterns.delete_at(0).first
          public_key = initiator_keypair_getter.call(message)
          @symmetric_state.mix_hash(public_key)
        end

        @protocol.pattern.responder_pre_messages&.map do |token|
          keypair = responder_keypair_getter.call(token)
          @symmetric_state.mix_hash(keypair)
        end
      end

      def expected_message_length(payload_size)
        has_key = @symmetric_state.cipher_state.key?
        pattern = @message_patterns.first
        len = pattern.inject(0) do |l, token|
          case token
          when 'e'
            l += @protocol.dh_fn.dhlen
            has_key = true if @protocol.psk_handshake?
          when 's'
            l += @protocol.dh_fn.dhlen
            l += 16 if has_key
          when 'ee', 'es', 'se', 'ss', 'psk'
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
        dh_fn = @protocol.dh_fn

        pattern.each do |token|
          case token
          when 'e'
            @e = dh_fn.generate_keypair if @e.nil?
            message_buffer << @e.public_key
            @symmetric_state.mix_hash(@e.public_key)
            @symmetric_state.mix_key(@e.public_key) if @protocol.psk_handshake?
          when 's'
            message_buffer << @symmetric_state.encrypt_and_hash(@s.public_key)
          when 'ee'
            @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @re))
          when 'es'
            private_key, public_key = @initiator ? [@e.private_key, @rs] : [@s.private_key, @re]
            @symmetric_state.mix_key(dh_fn.dh(private_key, public_key))
          when 'se'
            private_key, public_key = @initiator ? [@s.private_key, @re] : [@e.private_key, @rs]
            @symmetric_state.mix_key(dh_fn.dh(private_key, public_key))
          when 'ss'
            @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @rs))
          when 'psk'
            @symmetric_state.mix_key_and_hash(@connection.psks.shift)
          end
        end
        message_buffer << @symmetric_state.encrypt_and_hash(payload)
        @symmetric_state.split if @message_patterns.empty?
      end

      # Takes a byte sequence containing a Noise handshake message,
      # and a payload_buffer to write the message's plaintext payload into
      def read_message(message, payload_buffer)
        pattern = @message_patterns.shift
        dh_fn = @protocol.dh_fn
        len = dh_fn.dhlen
        pattern.each do |token|
          case token
          when 'e'
            @re = message[0...len] if @re.nil?
            message = message[len..-1]
            @symmetric_state.mix_hash(@re)
            @symmetric_state.mix_key(@re) if @protocol.psk_handshake?
          when 's'
            offset = @connection.cipher_state_handshake.key? ? 16 : 0
            temp = message[0...len + offset]
            message = message[(len + offset)..-1]
            @rs = @symmetric_state.decrypt_and_hash(temp)
          when 'ee'
            @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @re))
          when 'es'
            private_key, public_key = @initiator ? [@e.private_key, @rs] : [@s.private_key, @re]
            @symmetric_state.mix_key(dh_fn.dh(private_key, public_key))
          when 'se'
            private_key, public_key = @initiator ? [@s.private_key, @re] : [@e.private_key, @rs]
            @symmetric_state.mix_key(dh_fn.dh(private_key, public_key))
          when 'ss'
            @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @rs))
          when 'psk'
            @symmetric_state.mix_key_and_hash(@connection.psks.shift)
          end
        end
        payload_buffer << @symmetric_state.decrypt_and_hash(message)
        @symmetric_state.split if @message_patterns.empty?
      end
    end
  end
end
