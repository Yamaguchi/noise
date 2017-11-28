# frozen_string_literal: true

module Noise
  module Functions
    module Cipher
      autoload :AesGcm, 'noise/functions/cipher/aes_gcm'
      autoload :ChaChaPoly, 'noise/functions/cipher/cha_cha_poly'
    end
  end
end
