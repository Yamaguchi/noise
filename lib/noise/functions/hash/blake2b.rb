# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      class Blake2b
        HASHLEN = 64
        BLOCKLEN = 128
        def hash(data)
          RbNaCl::Hash.blake2b(data)
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
