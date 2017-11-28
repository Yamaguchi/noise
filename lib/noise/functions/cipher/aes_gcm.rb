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
      end
    end
  end
end
