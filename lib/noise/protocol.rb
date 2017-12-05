# frozen_string_literal: true

module Noise
  class Protocol
    attr_accessor :prologue, :initiator, :cipher_state_encrypt, :cipher_state_decrypt
    attr_reader :name, :cipher_fn, :hash_fn, :dh_fn, :hkdf_fn, :pattern
    attr_reader :handshake_state, :keypairs, :keypair_fn
    attr_reader :handshake_hash
    attr_accessor :cipher_state_handshake

    CIPHER = {
      'AESGCM': Noise::Functions::Cipher::AesGcm,
      'ChaChaPoly': Noise::Functions::Cipher::ChaChaPoly
    }.stringify_keys.freeze

    DH = {
      '25519': Noise::Functions::DH::DH25519,
      '448': Noise::Functions::DH::DH448
    }.stringify_keys.freeze

    HASH = {
      'BLAKE2b': Noise::Functions::Hash::Blake2b,
      'BLAKE2s': Noise::Functions::Hash::Blake2s,
      'SHA256': Noise::Functions::Hash::Sha256,
      'SHA512': Noise::Functions::Hash::Sha512
    }.stringify_keys.freeze

    def self.create(name)
      prefix, pattern_name, dh_name, cipher_name, hash_name = name.split('_')
      raise Noise::Exceptions::ProtocolNameError if prefix != 'Noise'
      new(name, pattern_name, cipher_name, hash_name, dh_name)
    end

    def initialize(name, pattern_name, cipher_name, hash_name, dh_name)
      @name = name
      @pattern = Noise::Pattern.create(pattern_name[0..1])
      @keypairs = { s: nil, e: nil, rs: nil, re: nil }
      @cipher_fn = CIPHER[cipher_name]&.new
      @hash_fn = HASH[hash_name]&.new
      @dh_fn = DH[dh_name]&.new
      @hkdf_fn = Noise::Functions::Hash.create_hkdf_fn(hash_name)
      raise Noise::Exceptions::ProtocolNameError unless @cipher_fn && @hash_fn && @dh_fn
    end

    def handshake_done
      if @pattern.one_way
        if @initiator
          @cipher_state_decrypt = nil
        else
          @cipher_state_encrypt = nil
        end
      end
      @handshake_hash = @symmetric_state.handshake_hash
      @handshake_state = nil
      @symmetric_state = nil
      @cipher_state_handshake = nil
      @prologue = nil
      @initiator = nil
      @dh_fn = nil
      @hash_fn = nil
      @keypair_fn = nil

    end

    def validate
      # TODO : support PSK
      # if @psk_handshake
      #   if @psks.inclueds? {|psk| psk.size != 32}
      #     raise NoisePSKError
      #   else
      #     raise NoisePSKError
      #   end
      # end

      # You need to set role with NoiseConnection.set_as_initiator
      # or NoiseConnection.set_as_responder
      raise Noise::Exceptions::NoiseValidationError if @initiator.nil?

      # 'Keypair {} has to be set for chosen handshake pattern'.format(keypair)
      # require 'pp'
      # pp @pattern
      # pp @initiator
      # pp @pattern.required_keypairs(@initiator)
      # pp @keypairs
      raise Noise::Exceptions::NoiseValidationError if @pattern.required_keypairs(@initiator).any? { |keypair| !@keypairs[keypair] }

      if @keypairs[:e] || @keypairs[:re]
        # warnings
        # One of ephemeral keypairs is already set.
        # This is OK for testing, but should NEVER happen in production!
      end
    end

    def initialise_handshake_state
      @handshake_state = Noise::State::HandshakeState.new(
        self,
        @initiator,
        @prologue,
        @keypairs[:s],
        @keypairs[:e],
        @keypairs[:rs],
        @keypairs[:re]
      )
      @symmetric_state = @handshake_state.symmetric_state
    end
  end
end
