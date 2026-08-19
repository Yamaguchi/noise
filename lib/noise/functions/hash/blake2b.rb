# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      class Blake2b
        HASHLEN = 64
        BLOCKLEN = 128

        # The name OpenSSL knows BLAKE2b with a 64 byte output by. OpenSSL only implements the
        # fixed 512 bit output length, which is exactly the HASHLEN the Noise specification gives
        # the BLAKE2b hash function.
        DIGEST_NAME = 'BLAKE2b512'

        def hash(data)
          OpenSSL::Digest.digest(DIGEST_NAME, data)
        end

        def hashlen
          HASHLEN
        end

        def blocklen
          BLOCKLEN
        end
      end

      # Builds an OpenSSL BLAKE2b digest with no argument, which is how HMAC::Base creates the
      # digests it feeds the inner and outer blocks to. OpenSSL defines no OpenSSL::Digest::BLAKE2b512
      # constant, so the algorithm name is bound here instead of being passed in at every call.
      class Blake2bDigester < OpenSSL::Digest
        def initialize
          super(Blake2b::DIGEST_NAME)
        end

        # HMAC::Base hashes a key longer than the block size through this class method. The one
        # inherited from OpenSSL::Digest takes the algorithm name as its first argument, which this
        # class has already bound, so it is redefined to take the data alone.
        def self.digest(data)
          new.digest(data)
        end
      end

      class Blake2bHMAC < HMAC::Base
        def initialize(key = nil)
          super(Blake2bDigester, Blake2b::BLOCKLEN, Blake2b::HASHLEN, key)
        end
        public_class_method :new, :digest, :hexdigest
      end
    end
  end
end
