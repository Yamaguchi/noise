# frozen_string_literal: true

module Noise
  module Functions
    module Cipher
      class AesGcm
        def encrypt(k, n, ad, plaintext)
          cipher = OpenSSL::Cipher::AES.new(256, :GCM).encrypt
          cipher.key = k
          cipher.iv = nonce_to_bytes(n)
          cipher.auth_data = ad
          cipher.update(plaintext) + cipher.final + cipher.auth_tag
        end

        def decrypt(k, n, ad, ciphertext)
          cipher = OpenSSL::Cipher::AES.new(256, :GCM).decrypt
          cipher.key = k
          cipher.iv = nonce_to_bytes(n)
          cipher.auth_data = ad
          cipher.auth_tag = ciphertext[-16..-1]
          cipher.update(ciphertext[0...-16]) + cipher.final
        end

        def nonce_to_bytes(n)
          "\x00" * 4 + format('%16x', n).htb
        end
      end
    end
  end
end
