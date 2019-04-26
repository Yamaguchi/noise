# frozen_string_literal: true

module Noise
  class Connection
    module Status
      STATIC = 1
      REMOTE_STATIC = 2
      EPHEMERAL = 3
      REMOTE_EPHEMERAL = 4
    end

    attr_accessor :protocol, :handshake_started, :handshake_finished, :fn

    def initialize(name)
      @protocol = Protocol.create(name)
      @handshake_started = false
      @handshake_finished = false
      @fn = nil
      @write_message_proc = ->(payload) { write_message(payload) }
      @read_message_proc = ->(payload) { read_message(payload) }
    end

    def psks=(psks)
      @protocol.psks = psks
    end

    def prologue=(prologue)
      @protocol.prologue = prologue
    end

    def set_as_initiator!
      @protocol.initiator = true
      @fn = @write_message_proc
    end

    def set_as_responder!
      @protocol.initiator = false
      @fn = @read_message_proc
    end

    def set_keypair_from_private(keypair, private_key)
      @protocol.keypairs[keypair.to_sym] = @protocol.dh_fn.class.from_private(private_key)
    end

    def set_keypair_from_public(keypair, public_key)
      @protocol.keypairs[keypair.to_sym] = public_key
    end

    def start_handshake
      @protocol.validate
      @protocol.initialise_handshake_state
      @handshake_started = true
    end

    def write_message(payload = '')
      # Call NoiseConnection.start_handshake first
      raise Noise::Exceptions::NoiseHandshakeError unless @handshake_started
      raise Noise::Exceptions::NoiseHandshakeError if @fn != @write_message_proc
      # Handshake finished. NoiseConnection.encrypt should be used now
      raise Noise::Exceptions::NoiseHandshakeError if @handshake_finished
      @fn = @read_message_proc
      buffer = +''
      result = @protocol.handshake_state.write_message(payload, buffer)
      @handshake_finished = true if result
      buffer
    end

    def read_message(data)
      # Call NoiseConnection.start_handshake first
      raise Noise::Exceptions::NoiseHandshakeError unless @handshake_started
      raise Noise::Exceptions::NoiseHandshakeError if @fn != @read_message_proc
      # Handshake finished. NoiseConnection.encrypt should be used now
      raise Noise::Exceptions::NoiseHandshakeError if @handshake_finished

      @fn = @write_message_proc
      buffer = +''
      result = @protocol.handshake_state.read_message(data, buffer)
      @handshake_finished = true if result
      buffer
    end

    def encrypt(data)
      raise Noise::Exceptions::NoiseHandshakeError unless @handshake_finished
      # raise Noise::Exceptions::NoiseInvalidMessage
      @protocol.cipher_state_encrypt.encrypt_with_ad('', data)
    end

    def decrypt(data)
      raise Noise::Exceptions::NoiseHandshakeError unless @handshake_finished
      # raise Noise::Exceptions::NoiseInvalidMessage
      @protocol.cipher_state_decrypt.decrypt_with_ad('', data)
    end
  end
end
