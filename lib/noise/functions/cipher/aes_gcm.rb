# frozen_string_literal: true

module Noise
  module Functions
    module Cipher
      class AesGcm
        def encrypt(k, n, ad, plaintext)
          throw NotImplementedError
        end

        def decrypt(k, n, ad, ciphertext)
          throw NotImplementedError
        end

        def nonce_to_bytes(n)
          "\00" * 4 + sprintf('%16x', n).htb
        end
      end
    end
  end
end
