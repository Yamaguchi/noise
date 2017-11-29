# frozen_string_literal: true

module Noise
  class Protocol
    attr_accessor :cipher_fn, :hash_fn, :dh_fn

    CIPHER = {
      'AESGCM': Noise::Functions::Cipher::AesGcm,
      'ChaChaPoly': Noise::Functions::Cipher::ChaChaPoly
    }.stringify_keys.freeze

    DH = {
      '25519': Noise::Functions::DH::DH25519,
      '448': Noise::Functions::DH::DH448
    }.stringify_keys.freeze

    HASH = {
      'SHA256': Noise::Functions::Hash::Sha256,
      'SHA512': Noise::Functions::Hash::Sha512
    }.stringify_keys.freeze

    def self.create(name)
      prefix, pattern_name, dh_name, cipher_name, hash_name = name.split('_')
      raise Noise::Exceptions::ProtocolNameError if prefix != 'Noise'
      new(pattern_name, cipher_name, hash_name, dh_name)
    end

    def initialize(pattern_name, cipher_name, hash_name, dh_name)
      @cipher_fn = CIPHER[cipher_name]&.new
      @hash_fn = HASH[hash_name]&.new
      @dh_fn = DH[dh_name]&.new
      @hkdf_fn = Noise::Functions::Hash.create_hkdf_fn(hash_name)
      raise Noise::Exceptions::ProtocolNameError unless @cipher_fn && @hash_fn && @dh_fn
    end
  end
end
