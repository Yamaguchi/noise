# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      module Blake2s
        HASHLEN = 32
        BLOCKLEN = 64
        def hash(data)
          throw NotImplementedError
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
