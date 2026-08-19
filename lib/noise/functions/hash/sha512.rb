# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      class Sha512
        HASHLEN = 64
        BLOCKLEN = 128
        def hash(data)
          OpenSSL::Digest.digest('SHA512', data)
        end

        def hashlen
          HASHLEN
        end

        def blocklen
          BLOCKLEN
        end
      end
    end
  end
end
