# frozen_string_literal: true

require_force 'blake3'

module Noise
  module Functions
    module Hash
      class Blake3
        HASHLEN = 64
        BLOCKLEN = 128
        def hash(data)
          ::Blake3.digest(data)
        end

        def hashlen
          HASHLEN
        end

        def blocklen
          BLOCKLEN
        end
      end

      class Blake3HMAC < HMAC::Base
        def initialize(key = nil)
          super(::Blake3::Hasher, Blake3::BLOCKLEN, Blake3::HASHLEN, key)
        end
        public_class_method :new, :digest, :hexdigest
      end
    end
  end
end
