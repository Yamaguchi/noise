# frozen_string_literal: true

module Noise
  module State
    # A CipherState can encrypt and decrypt data based on its k and n variables:
    #
    # - k: A cipher key of 32 bytes (which may be empty). Empty is a special value which indicates k has not yet been
    # initialized.
    # - n: An 8-byte (64-bit) unsigned integer nonce.
    #
    class CipherState
      MAX_NONCE = 2**64 - 1

      attr_reader :k, :n

      def initialize(cipher: AesGcm.new)
        @cipher = cipher
      end

      # @param [String] 32 bytes key
      def initialize_key(key)
        @k = key
        @n = 0
      end

      # @return [Boolean] true if k is non-empty, false otherwise.
      def key?
        !@k.nil?
      end

      def nonce=(nonce)
        @n = nonce
      end

      #  @return [String] ENCRYPT(k, n++, ad, plaintext) if k is non-empty, otherwise returns plaintext.
      def encrypt_with_ad(ad, plaintext)
        return plaintext unless key?
        raise Noise::Exceptions::MaxNonceError if @n == MAX_NONCE
        ciphertext = @cipher.encrypt(@k, @n, ad, plaintext)
        @n += 1
        ciphertext
      end

      # @return DECRYPT(k, n++, ad, ciphertext) if k is non-empty, otherwise returns ciphertext.
      def decrypt_with_ad(ad, ciphertext)
        return ciphertext unless key?
        raise Noise::Exceptions::MaxNonceError if @n == MAX_NONCE
        plaintext = @cipher.decrypt(@k, @n, ad, ciphertext)
        @n += 1
        plaintext
      end

      def rekey
        @k = @cipher.rekey(@k)
      end
    end
  end
end
