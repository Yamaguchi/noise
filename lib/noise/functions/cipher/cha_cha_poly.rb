# frozen_string_literal: true

module Noise
  module Functions
    module Cipher
      class ChaChaPoly
        MAX_NONCE = 2**64 - 1

        def encrypt(k, n, ad, plaintext)
          cipher = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(String.new(k).force_encoding('ASCII-8BIT'))
          cipher.encrypt(nonce_to_bytes(n), plaintext, ad)
        rescue ::RbNaCl::CryptoError => e
          raise Noise::Exceptions::EncryptError, e
        end

        def decrypt(k, n, ad, ciphertext)
          cipher = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(String.new(k).force_encoding('ASCII-8BIT'))
          cipher.decrypt(nonce_to_bytes(n), ciphertext, ad)
        rescue ::RbNaCl::CryptoError => e
          raise Noise::Exceptions::DecryptError, e
        end

        def nonce_to_bytes(n)
          "\x00" * 4 + format('%16x', n).htb.reverse
        end

        # Returns a new 32-byte cipher key as a pseudorandom function of k.
        # If this function is not specifically defined for some set of cipher
        # functions, then it defaults to returning the first 32 bytes from
        # ENCRYPT(k,maxnonce, zerolen, zeros), where  maxnonce equals 2**64-1,
        # zerolen is a zero-length byte sequence, and zeros is a sequence of
        # 32 bytes filled with zeros.
        def rekey(k)
          encrypt(k, MAX_NONCE, '', "\x00" * 32)[0..32]
        end
      end
    end
  end
end
