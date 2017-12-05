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

      attr_reader :message_patterns, :symmetric_state

      def initialize(protocol, initiator, prologue, s, e, rs, re)
        # @protocol = handshake_pattern.to_protocol
        @protocol = protocol
        @symmetric_state = SymmetricState.new
        @symmetric_state.initialize_symmetric(@protocol)
        puts "prologue=#{prologue}"
        @symmetric_state.mix_hash(prologue)
        @initiator = initiator
        @s = s
        @e = e
        @rs = rs
        @re = re

        # TODO : Calls MixHash() once for each public key listed in the pre-messages from  handshake_pattern, with the
        # specified public key as input (see Section 7 for an explanation of pre-messages). If both initiator and
        # responder have pre-messages, the initiator's public keys are hashed first.
        # if initiator
        #   @_get_local_keypair
        #   @symmetric_state.mix_hash()
        # else
        #   public_key =
        #   @symmetric_state.mix_hash(public_key)
        # end
        # initiator_keypair_getter = instance._get_local_keypair if initiator else instance._get_remote_keypair
        # responder_keypair_getter = instance._get_remote_keypair if initiator else instance._get_local_keypair
        # for keypair in map(initiator_keypair_getter, noise_protocol.pattern.get_initiator_pre_messages())
        #     instance.symmetric_state.mix_hash(keypair.public_bytes)
        # for keypair in map(responder_keypair_getter, noise_protocol.pattern.get_responder_pre_messages())
        #     instance.symmetric_state.mix_hash(keypair.public_bytes)

        # Sets message_patterns to the message patterns from handshake_pattern
        @message_patterns = @protocol.pattern.tokens.dup
      end

      def write_message(payload, message_buffer)
        puts "HandshakeState#write_message---------"
        puts "patterns=#{@message_patterns}"
        puts "    payload=#{payload}"
        pattern = @message_patterns.shift
        puts "    pattern=#{pattern}"
        dh_fn = @protocol.dh_fn
        pattern.each do |token|
          puts "    token=#{token}"
          case token
          when 'e'
            @e = dh_fn.generate_keypair if @e.nil?
            message_buffer << @e[1]
            @symmetric_state.mix_hash(@e[1])
            next
          when 's'
            message_buffer << @symmetric_state.encrypt_and_hash(@s[1])
            next
          when 'ee'
            @symmetric_state.mix_key(dh_fn.dh(@e[0], @re))
            next
          when 'es'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@e[0], @rs))
            else
              @symmetric_state.mix_key(dh_fn.dh(@s[0], @re))
            end
            next
          when 'se'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@s[0], @re))
            else
              @symmetric_state.mix_key(dh_fn.dh(@e[0], @rs))
            end
            next
          when 'ss'
            @symmetric_state.mix_key(dh_fn.dh(@s[0], @rs))
            next
          end
        end
        puts "    call encrypt_and_hash"
        message_buffer << @symmetric_state.encrypt_and_hash(payload)
        puts "    message_buffer=#{message_buffer.bth}"
        @symmetric_state.split if @message_patterns.empty?
      end

      def read_message(message, payload_buffer)
        puts "HandshakeState#read_message------------------"
        pattern = @message_patterns.shift
        dh_fn = @protocol.dh_fn
        len = dh_fn.dhlen
        pattern.each do |token|
          puts "    token=#{token}"
          case token
          when 'e'
            @re = @protocol.dh_fn.class.from_public(message[0...len])[1] if @re.nil?
            message = message[len..-1]
            @symmetric_state.mix_hash(@re)
            next
          when 's'
            offset = @protocol.cipher_state_handshake.key? ? 16 : 0
            temp = message[0...len + offset]
            message = message[(len + offset)..-1]
            @rs = @protocol.dh_fn.class.from_public(@symmetric_state.decrypt_and_hash(temp))[1]
            # @protocol.keypair.load(@symmetric_state.decrypt_and_hash(temp))
            next
          when 'ee'
            @symmetric_state.mix_key(dh_fn.dh(@e[0], @re))
            next
          when 'es'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@e[0], @rs))
            else
              @symmetric_state.mix_key(dh_fn.dh(@s[0], @re))
            end
            next
          when 'se'
            if @initiator
              @symmetric_state.mix_key(dh_fn.dh(@s[0], @re))
            else
              @symmetric_state.mix_key(dh_fn.dh(@e[0], @rs))
            end
            next
          when 'ss'
            @symmetric_state.mix_key(dh_fn.dh(@s[0], @rs))
            next
          end
        end
        payload_buffer << @symmetric_state.decrypt_and_hash(message)
        puts "    payload_buffer=#{payload_buffer.bth}"
        @symmetric_state.split if @message_patterns.empty?
      end
    end

    # def _get_local_keypair(token:)
    #   keypair = getattr(self, token)  # Maybe explicitly handle exception when getting improper keypair
    #   if isinstance(keypair, Empty)
    #     raise Exception('Required keypair {} is empty!'.format(token))  # Maybe subclassed exception
    #   return keypair
    # end
    #
    # def _get_remote_keypair(token)
    #   keypair = getattr(self, 'r' + token)  # Maybe explicitly handle exception when getting improper keypair
    #   if isinstance(keypair, Empty)
    #     raise Exception('Required keypair {} is empty!'.format('r' + token))  # Maybe subclassed exception
    #   return keypair
    # end
  end
end
