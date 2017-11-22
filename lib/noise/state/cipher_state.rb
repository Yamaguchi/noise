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
      def initialize(cipher: AesGcm.new)
        @cipher = cipher
      end

      def initialize_key(key)
        @k = key
        @n = 0
      end

      def key?
        !@k.nil?
      end

      def nonce=(nonce)
        @n = nonce
      end

      def encrypt_with_ad(ad, plaintext)
        return plaintext unless key?
        raise MaxNonceError if @n == MAX_NONCE
        ciphertext = @cipher.encrypt(@k, @n, ad, plaintext)
        @n += 1
        ciphertext
      end

      def decrypt_with_ad(ad, ciphertext)
        return ciphertext unless key?
        raise MaxNonceError if @n == MAX_NONCE
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