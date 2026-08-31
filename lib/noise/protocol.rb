# frozen_string_literal: true

module Noise
  class Protocol
    attr_accessor :cipher_fn, :hash_fn, :dh_fn, :hkdf_fn
    attr_reader :name, :pattern, :protocol_name

    CIPHER = {
      'AESGCM' => Noise::Functions::Cipher::AesGcm,
      'ChaChaPoly' => Noise::Functions::Cipher::ChaChaPoly
    }.freeze

    DH = {
      '25519' => Noise::Functions::DH::ED25519,
      '448' => Noise::Functions::DH::ED448,
      'secp256k1' => Noise::Functions::DH::Secp256k1
    }.freeze

    HASH = {
      'BLAKE2b' => Noise::Functions::Hash::Blake2b,
      'BLAKE2s' => Noise::Functions::Hash::Blake2s,
      'SHA256' => Noise::Functions::Hash::Sha256,
      'SHA512' => Noise::Functions::Hash::Sha512,
      'BLAKE3' => Noise::Functions::Hash::Blake3
    }.freeze

    # @param [String] name the protocol name, for example 'Noise_XX_25519_ChaChaPoly_SHA256'.
    # @raise [Noise::Exceptions::ProtocolNameError] if the name is malformed, or names a pattern
    #   or a function this gem does not implement.
    # @raise [Noise::Exceptions::UnsupportedModifierError] if it names a modifier this gem does
    #   not implement.
    # @return [Noise::Protocol]
    def self.create(name)
      new(Noise::ProtocolName.parse(name))
    end

    # @param [Noise::ProtocolName] protocol_name the parsed name this protocol runs.
    def initialize(protocol_name)
      @protocol_name = protocol_name
      @name = protocol_name.name
      @pattern = Noise::Pattern.create(protocol_name.pattern_name, protocol_name.modifiers)
      @hkdf_fn = Noise::Functions::Hash.create_hkdf_fn(protocol_name.hash_name)
      @pattern.apply_pattern_modifiers

      initialize_fn!
    end

    def psk?
      @pattern.psk?
    end

    private

    # Looks the three functions up by the names the protocol name gives them.
    #
    # @raise [Noise::Exceptions::ProtocolNameError] if any of the three is one this gem does not
    #   implement.
    def initialize_fn!
      @cipher_fn = CIPHER[@protocol_name.cipher_name]&.new
      @hash_fn = HASH[@protocol_name.hash_name]&.new
      @dh_fn = create_dh_fn(@protocol_name.dh_names)
      raise Noise::Exceptions::ProtocolNameError, "Unsupported function in: #{@name}" unless
        @cipher_fn && @hash_fn && @dh_fn
    end

    # A name may list more than one DH function, joined with '+', which is how a hybrid handshake
    # is written. This gem runs a single DH function, so any name that lists more than one, or
    # that leaves a member of the list empty, resolves to nothing and is reported as unsupported.
    #
    # The hybrid names the Noise extensions define also carry a modifier, hfs, which
    # Noise::ProtocolName rejects first, so what reaches here today is a name that lists several
    # DH functions and nothing else.
    #
    # @param [Array<String>] names the DH function names the protocol name lists.
    # @return [Object, nil] the DH function, or nil if the name asks for one this gem lacks.
    def create_dh_fn(names)
      return nil unless names.size == 1

      DH[names.first]&.new
    end
  end
end
