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
      TAG_LENGTH = 16

      attr_reader :k, :n

      def initialize(cipher:)
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

      # Sets n, the nonce the next encrypt_with_ad or decrypt_with_ad call uses. This is SetNonce()
      # of the Noise spec, needed to decrypt transport messages that arrive out of order.
      #
      # The value is checked here because the ciphers pack n into 8 bytes: a value outside the
      # unsigned 64-bit range silently produces a wrong nonce instead of an error.
      #
      # @param [Integer] nonce a value between 0 and MAX_NONCE.
      # @raise [Noise::Exceptions::InvalidNonceError] if nonce is out of that range.
      def nonce=(nonce)
        raise Noise::Exceptions::InvalidNonceError unless nonce.is_a?(Integer) && nonce.between?(0, MAX_NONCE)

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
        # Without this the ciphers slice a nil authentication tag out of the truncated input.
        raise Noise::Exceptions::DecryptError, 'Ciphertext is shorter than the tag.' if
          ciphertext.bytesize < TAG_LENGTH

        plaintext = @cipher.decrypt(@k, @n, ad, ciphertext)
        @n += 1
        plaintext
      end

      # Replaces k with REKEY(k). n is left as it is, as the Noise spec requires.
      #
      # @return [String] the new 32 bytes key.
      def rekey
        @k = @cipher.rekey(@k)
      end
    end
  end
end
