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
    class HandshakeState
      def initialize(handshake_pattern, initiator, prologue, s, e, rs, re)
        protocol = handshake_pattern.to_protocol
        @symmetric_state = SymmetricState.new
        @symmetric_state.initialize_symmetric(protocol.name)
        @symmetric_state.mix_hash(prologue)
        @initiator = initiator
        @s = s
        @e = e
        @rs = rs
        @re = re

        # TODO : Calls MixHash() once for each public key listed in the pre-messages from  handshake_pattern, with the
        # specified public key as input (see Section 7 for an explanation of pre-messages). If both initiator and
        # responder have pre-messages, the initiator's public keys are hashed first.

        # TODO : Sets message_patterns to the message patterns from handshake_pattern
        @message_patterns = handshake_pattern.message_patterns
      end

      def write_message(payload, message_buffer)
        pattern = @message_patterns.pop
        dh_fn = @protocol.dh_fn
        pattern.each do |token|
          case token
          when 'e'
            @e = dh_fn.generate_keypair if @e.nil?
            message_buffer << @e.public_key
            @symmetric_state.mix_hash(@e.public_key)
            break
          when 's'
            message_buffer << @symmetric_state.encrypt_and_hash(@s.public_key)
            break
          when 'ee'
            @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @re.public_key))
            break
          when 'es'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @rs.public_key))
            else
              @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @re.public_key))
            end
            break
          when 'se'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @re.public_key))
            else
              @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @rs.public_key))
            end
            break
          when 'ss'
            @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @rs.public_key))
            break
          end
        end
        message_buffer << @symmetric_state.encrypt_and_hash(payload)
        @symmetric_state.split if @message_patterns.empty?
      end

      def read_message(message, payload_buffer)
        pattern = @message_patterns.pop
        dh_fn = @protocol.dh_fn
        len = dh_fn.dhlen
        pattern.each do |token|
          case token
          when 'e'
            @re = @protocol.keypair_fn.load(message[0, len]) if @re.nil?
            message = message[len..-1]
            @symmetric_state.mix_hash(@re.public_key)
            break
          when 's'
            offset = @protocol.cipher_state_handshake.key? ? 16 : 0
            temp = message[0, len + offset]
            message = message[(len + offset)..-1]
            @rs = @protocol.keypair_fn.load(@symmetric_state.decrypt_and_hash(temp))
            break
          when 'ee'
            @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @re.public_key))
            break
          when 'es'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @rs.public_key))
            else
              @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @re.public_key))
            end
            break
          when 'se'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @re.public_key))
            else
              @symmetric_state.mix_key(dh_fn.dh(@e.private_key, @rs.public_key))
            end
            break
          when 'ss'
            @symmetric_state.mix_key(dh_fn.dh(@s.private_key, @rs.public_key))
            break
          end
        end
        payload_buffer << @symmetric_state.decrypt_and_hash(message)
        @symmetric_state.split if @message_patterns.empty?
      end
    end
  end
end
