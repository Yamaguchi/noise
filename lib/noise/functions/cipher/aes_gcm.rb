# frozen_string_literal: true

module Noise
  module Functions
    module Cipher
      class AesGcm
        MAX_NONCE = 2**64 - 1

        def encrypt(k, n, ad, plaintext)
          cipher = OpenSSL::Cipher::AES.new(256, :GCM).encrypt
          cipher.key = k
          cipher.iv = nonce_to_bytes(n)
          cipher.auth_data = ad
          cipher.update(plaintext) + cipher.final + cipher.auth_tag
        rescue OpenSSL::Cipher::CipherError => e
          raise Noise::Exceptions::EncryptError, "Encrypt failed. #{e.message}", e.backtrace
        end

        def decrypt(k, n, ad, ciphertext)
          cipher = OpenSSL::Cipher::AES.new(256, :GCM).decrypt
          cipher.key = k
          cipher.iv = nonce_to_bytes(n)
          cipher.auth_data = ad
          cipher.auth_tag = ciphertext[-16..-1]
          cipher.update(ciphertext[0...-16]) + cipher.final
        rescue OpenSSL::Cipher::CipherError => e
          raise Noise::Exceptions::DecryptError, "Decrpyt failed. #{e.message}", e.backtrace
        end

        def nonce_to_bytes(n)
          "\x00" * 4 + format('%16x', n).htb
        end

        # Returns a new 32-byte cipher key as a pseudorandom function of k.
        # If this function is not specifically defined for some set of cipher
        # functions, then it defaults to returning the first 32 bytes from
        # ENCRYPT(k,maxnonce, zerolen, zeros), where  maxnonce equals 264-1,
        # zerolen is a zero-length byte sequence, and zeros is a sequence of
        # 32 bytes filled with zeros.
        def rekey(k)
          encrypt(k, MAX_NONCE, '', "\x00" * 32)[0...32]
        end
      end
    end
  end
end
