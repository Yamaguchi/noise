# frozen_string_literal: true

module Noise
  module Functions
    module Cipher
      class ChaChaPoly
        def encrypt(k, n, ad, plaintext)
          @cipher = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(String.new(k).force_encoding('ASCII-8BIT'))
          @cipher.encrypt(nonce_to_bytes(n), plaintext, ad)
        rescue ::RbNaCl::CryptoError => e
          raise Noise::Exceptions::EncryptError.new(e)
        end

        def decrypt(k, n, ad, ciphertext)
          @cipher = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(String.new(k).force_encoding('ASCII-8BIT'))
          @cipher.decrypt(nonce_to_bytes(n), ciphertext, ad)
        rescue ::RbNaCl::CryptoError => e
          raise Noise::Exceptions::DecryptError.new(e)
        end

        def nonce_to_bytes(n)
          "\x00" * 4 + format('%16x', n).htb.reverse
        end
      end
    end
  end
end
