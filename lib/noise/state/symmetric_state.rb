# frozen_string_literal: true

module Noise
  module State
    # A SymmetricState object contains a CipherState plus the following variables:
    #
    # - ck: A chaining key of HASHLEN bytes.
    # - h: A hash output of HASHLEN bytes.
    #
    class SymmetricState
      attr_reader :h, :ck
      attr_reader :cipher_state

      def initialize_symmetric(protocol)
        @protocol = protocol
        @ck = @h =
                if @protocol.name.length <= @protocol.hash_fn.hashlen
                  @protocol.name.ljust(@protocol.hash_fn.hashlen, "\x00")
                else
                  @protocol.hash_fn.hash(@protocol.name)
                end

        @cipher_state = CipherState.new(cipher: @protocol.cipher_fn)
        @cipher_state.initialize_key(nil)
        @protocol.cipher_state_handshake = @cipher_state
      end

      def mix_key(input_key_meterial)
        @ck, temp_k = @protocol.hkdf_fn.call(@ck, input_key_meterial, 2)
        temp_k = truncate(temp_k)
        @cipher_state.initialize_key(temp_k)
      end

      # data [String] binary string
      def mix_hash(data)
        @h = @protocol.hash_fn.hash(@h + data)
      end

      def mix_key_and_hash(input_key_meterial)
        @ck, temp_h, temp_k = @protocol.hkdf_fn.call(@ck, input_key_meterial, 3)
        mix_hash(temp_h)
        temp_k = truncate(temp_k)
        @cipher_state.initialize_key(temp_k)
      end

      def handshake_hash
        @h
      end

      def encrypt_and_hash(plaintext)
        ciphertext = @cipher_state.encrypt_with_ad(@h, plaintext)
        mix_hash(ciphertext)
        ciphertext
      end

      def decrypt_and_hash(ciphertext)
        plaintext = @cipher_state.decrypt_with_ad(@h, ciphertext)
        mix_hash(ciphertext)
        plaintext
      end

      def split
        temp_k1, temp_k2 = @protocol.hkdf_fn.call(@ck, '', 2)
        temp_k1 = truncate(temp_k1)
        temp_k2 = truncate(temp_k2)
        c1 = CipherState.new(cipher: @protocol.cipher_fn)
        c2 = CipherState.new(cipher: @protocol.cipher_fn)
        c1.initialize_key(temp_k1)
        c2.initialize_key(temp_k2)
        @protocol.cipher_state_encrypt = @protocol.initiator ? c1 : c2
        @protocol.cipher_state_decrypt = @protocol.initiator ? c2 : c1
        @protocol.handshake_done
        [c1, c2]
      end

      def truncate(temp_k)
        @protocol.hash_fn.hashlen == 64 ? temp_k[0, 32] : temp_k
      end
    end
  end
end
