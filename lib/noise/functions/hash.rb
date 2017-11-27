# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      autoload :Blake2b, 'noise/functions/hash/blake2b'
      autoload :Blake2s, 'noise/functions/hash/blake2s'
      autoload :Sha256, 'noise/functions/hash/sha256'
      autoload :Sha512, 'noise/functions/hash/sha512'
    end
  end
end
