# frozen_string_literal: true

module Noise
  module Functions
    module Cipher
      class ChaChaPoly
        MAX_NONCE = 2**64 - 1

        # The name OpenSSL knows the AEAD construction of RFC 8439 by. It takes a 12 byte nonce and
        # produces a 16 byte authentication tag, which is what the Noise specification requires of
        # the ChaChaPoly cipher functions.
        ALGORITHM = 'chacha20-poly1305'

        # Length in bytes of the authentication tag that encrypt appends to the ciphertext.
        TAGLEN = 16

        def encrypt(k, n, ad, plaintext)
          cipher = OpenSSL::Cipher.new(ALGORITHM).encrypt
          cipher.key = k
          cipher.iv = nonce_to_bytes(n)
          cipher.auth_data = ad
          update(cipher, plaintext) + cipher.final + cipher.auth_tag
        rescue OpenSSL::Cipher::CipherError => e
          raise Noise::Exceptions::EncryptError, "Encrypt failed. #{e.message}", e.backtrace
        end

        def decrypt(k, n, ad, ciphertext)
          cipher = OpenSSL::Cipher.new(ALGORITHM).decrypt
          cipher.key = k
          cipher.iv = nonce_to_bytes(n)
          cipher.auth_data = ad
          cipher.auth_tag = ciphertext[-TAGLEN..]
          update(cipher, ciphertext[0...-TAGLEN]) + cipher.final
        rescue OpenSSL::Cipher::CipherError => e
          raise Noise::Exceptions::DecryptError, "Decrpyt failed. #{e.message}", e.backtrace
        end

        # 4 zero bytes followed by n as a little-endian 64 bit integer.
        def nonce_to_bytes(n)
          "\x00" * 4 + [n].pack('Q<')
        end

        # Returns a new 32-byte cipher key as a pseudorandom function of k.
        # If this function is not specifically defined for some set of cipher
        # functions, then it defaults to returning the first 32 bytes from
        # ENCRYPT(k,maxnonce, zerolen, zeros), where  maxnonce equals 2**64-1,
        # zerolen is a zero-length byte sequence, and zeros is a sequence of
        # 32 bytes filled with zeros.
        def rekey(k)
          encrypt(k, MAX_NONCE, '', "\x00" * 32)[0...32]
        end

        private

        # A zero-length payload is normal in a Noise message, but OpenSSL::Cipher#update raises
        # ArgumentError('data must not be empty') instead of returning ''.
        def update(cipher, data)
          return String.new if data.empty?

          cipher.update(data)
        end
      end
    end
  end
end
