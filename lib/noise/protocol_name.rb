# frozen_string_literal: true

module Noise
  # A Noise protocol name, split into the parts that name a handshake pattern and the three
  # functions the protocol runs on.
  #
  # A name has five parts joined with '_': the prefix 'Noise', the handshake pattern with its
  # modifiers, the DH function, the cipher function and the hash function, for example
  # 'Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s'.
  #
  # Two of those parts hold a list of their own. The pattern part is a pattern name followed by
  # the modifiers applied to it, and the DH part is a list joined with '+', because a hybrid
  # handshake names two DH functions at once ('Noise_NNhfs_25519+448_ChaChaPoly_BLAKE2s'). Both
  # are split here, so that every rule about the shape of a name lives in this class alone.
  #
  # Which functions exist is Noise::Protocol's question, not this one's: a name that asks for a
  # cipher, hash or DH function this gem does not implement still parses. Modifiers are the one
  # exception, because a modifier has to be understood before it can be held as a value, so an
  # unknown one is rejected here.
  #
  # The members are the names as written, not the functions themselves. Noise::Protocol resolves
  # them, and calls its resolved functions cipher_fn, hash_fn and dh_fn.
  ProtocolName = Data.define(:name, :pattern_name, :modifiers, :dh_names, :cipher_name,
                             :hash_name) do
    # Parses a protocol name.
    #
    # @param [String] name for example 'Noise_XX_25519_ChaChaPoly_SHA256'.
    # @raise [Noise::Exceptions::ProtocolNameError] if the name is not five parts with the 'Noise'
    #   prefix and a pattern part whose modifiers can be told from the pattern name.
    # @raise [Noise::Exceptions::UnsupportedModifierError] if a modifier is written correctly but
    #   is not one this gem implements.
    # @return [Noise::ProtocolName]
    def self.parse(name)
      # 'Noise', the pattern with its modifiers, the DH functions, the cipher and the hash.
      parts = name.split('_')
      malformed!(name) unless parts.size == 5

      prefix, pattern_part, dh_part, cipher_name, hash_name = parts
      malformed!(name) unless prefix == 'Noise'

      # A pattern name is capitals, plus the digit 1 that deferred patterns use (X1K1). Whatever
      # follows it is the modifiers.
      matched = /\A([A-Z1]+)([^A-Z]*)\z/.match(pattern_part)
      malformed!(name) unless matched

      new(name: name, pattern_name: matched[1], modifiers: parse_modifiers(matched[2]),
          dh_names: split_dh(dh_part), cipher_name: cipher_name, hash_name: hash_name)
    end

    # @param [String] part the modifiers as written, which is '' when there are none.
    # @return [Array] the modifiers, in the order the name writes them.
    def self.parse_modifiers(part)
      part.split('+').map { |modifier| Modifier.parse(modifier) }.freeze
    end
    private_class_method :parse_modifiers

    # Keeps the empty members a stray '+' leaves behind, so that '25519+' reads as two DH
    # functions, the second of which has no name, rather than as the single function '25519'.
    # Nothing resolves an empty name, so such a name is reported as unsupported.
    #
    # @param [String] part the DH functions as written.
    # @return [Array<String>] one name per member.
    def self.split_dh(part)
      part.split('+', -1).freeze
    end
    private_class_method :split_dh

    def self.malformed!(name)
      raise Noise::Exceptions::ProtocolNameError, "Malformed protocol name: #{name}"
    end
    private_class_method :malformed!

    # @return [String] the name this was parsed from.
    def to_s
      name
    end
  end
end
