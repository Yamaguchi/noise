# frozen_string_literal: true

module Noise
  class Protocol
    attr_accessor :is_psk_handshake
    attr_accessor :cipher_fn, :hash_fn, :dh_fn, :hkdf_fn
    attr_reader :name, :pattern

    CIPHER = {
      'AESGCM': Noise::Functions::Cipher::AesGcm,
      'ChaChaPoly': Noise::Functions::Cipher::ChaChaPoly
    }.stringify_keys.freeze

    DH = {
      '25519': Noise::Functions::DH::ED25519,
      '448': Noise::Functions::DH::ED448,
      'secp256k1': Noise::Functions::DH::Secp256k1
    }.stringify_keys.freeze

    HASH = {
      'BLAKE2b': Noise::Functions::Hash::Blake2b,
      'BLAKE2s': Noise::Functions::Hash::Blake2s,
      'SHA256': Noise::Functions::Hash::Sha256,
      'SHA512': Noise::Functions::Hash::Sha512,
      'BLAKE3': Noise::Functions::Hash::Blake3,
    }.stringify_keys.freeze

    def self.create(name)
      prefix, pattern_name, dh_name, cipher_name, hash_name = name.split('_')
      raise Noise::Exceptions::ProtocolNameError if prefix != 'Noise'
      new(name, pattern_name, cipher_name, hash_name, dh_name)
    end

    def initialize(name, pattern_name, cipher_name, hash_name, dh_name)
      @name = name
      @pattern = Noise::Pattern.create(pattern_name)
      @hkdf_fn = Noise::Functions::Hash.create_hkdf_fn(hash_name)
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

    def psk_handshake?
      @is_psk_handshake
    end
  end
end
