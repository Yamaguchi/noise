# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      module Sha256
        HASHLEN = 32
        BLOCKLEN = 64
        def hash(data)
          RbNaCl::Hash.sha256(data)
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
