# frozen_string_literal: true

module Noise
  class Protocol
    attr_accessor :prologue, :initiator
    attr_accessor :cipher_state_encrypt, :cipher_state_decrypt
    attr_accessor :cipher_state_handshake
    attr_accessor :psks
    attr_reader :name, :cipher_fn, :hash_fn, :dh_fn, :hkdf_fn, :pattern
    attr_reader :handshake_state, :keypairs, :keypair_fn
    attr_reader :handshake_hash

    CIPHER = {
      'AESGCM': Noise::Functions::Cipher::AesGcm,
      'ChaChaPoly': Noise::Functions::Cipher::ChaChaPoly
    }.stringify_keys.freeze

    DH = {
      '25519': Noise::Functions::DH::ED25519,
      '448': Noise::Functions::DH::ED448
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
      @pattern = Noise::Pattern.create(pattern_name)
      @keypairs = { s: [], e: [], rs: [], re: [] }
      @hkdf_fn = Noise::Functions::Hash.create_hkdf_fn(hash_name)
      @psks = []
      @is_psk_handshake = @pattern.modifiers.any? { |m| m.start_with?('psk') }

      @pattern.apply_pattern_modifiers

      initialize_fn!(cipher_name, hash_name, dh_name)
    end

    def initialize_fn!(cipher_name, hash_name, dh_name)
      @cipher_fn = CIPHER[cipher_name]&.new
      @hash_fn = HASH[hash_name]&.new
      @dh_fn = DH[dh_name]&.new
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

    def validate_psk!
      # Invalid psk length! Has to be 32 bytes long
      raise Noise::Exceptions::NoisePSKError if @psks.any? { |psk| psk.bytesize != 32 }
      # Bad number of PSKs provided to this protocol! {} are required,
      # given {}'.format(self.pattern.psk_count, len(self.psks)))
      raise Noise::Exceptions::NoisePSKError if @pattern.psk_count != @psks.count
    end

    def valid_keypairs?
      @pattern.required_keypairs(@initiator).any? { |keypair| !@keypairs[keypair] }
    end

    def validate
      validate_psk! if psk_handshake?

      # You need to set role with NoiseConnection.set_as_initiator
      # or NoiseConnection.set_as_responder
      raise Noise::Exceptions::NoiseValidationError if @initiator.nil?

      # 'Keypair {} has to be set for chosen handshake pattern'.format(keypair)
      raise Noise::Exceptions::NoiseValidationError if valid_keypairs?

      if @keypairs[:e] || @keypairs[:re]
        # warnings
        # One of ephemeral keypairs is already set.
        # This is OK for testing, but should NEVER happen in production!
      end
      true
    end

    def initialise_handshake_state
      @handshake_state = Noise::State::HandshakeState.new(
        self,
        @initiator,
        @prologue,
        @keypairs
      )
      @symmetric_state = @handshake_state.symmetric_state
    end

    def psk_handshake?
      @is_psk_handshake
    end
  end
end
