# frozen_string_literal: true

require 'aead'

module Noise
  module Functions
    module Cipher
      class AesGcm
        def encrypt(k, n, ad, plaintext)
          mode = AEAD::Cipher.new('AES-256-GCM')
          cipher = mode.new(k)
          cipher.encrypt(nonce_to_bytes(n), ad, plaintext)
        end

        def decrypt(k, n, ad, ciphertext)
          mode = AEAD::Cipher.new('AES-256-GCM')
          cipher = mode.new(k)
          cipher.decrypt(nonce_to_bytes(n), ad, ciphertext)
        end

        def nonce_to_bytes(n)
          "\00" * 4 + format('%16x', n).htb
        end
      end
    end
  end
end
