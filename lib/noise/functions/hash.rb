# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      autoload :Blake2b, 'noise/functions/hash/blake2b'
      autoload :Blake2s, 'noise/functions/hash/blake2s'
      autoload :Sha256, 'noise/functions/hash/sha256'
      autoload :Sha512, 'noise/functions/hash/sha512'

      def self.hmac_hash(key, data, digest)
        # TODO: support for blake2b, blake2s
        if digest.include?('SHA')
          OpenSSL::HMAC.digest(OpenSSL::Digest.new(digest), key, data)
        elsif digest.include?('BLAKE2b')
          Noise::Functions::Hash::Blake2bHMAC.new(key).update(data).digest
        end
      end

      def self.create_hkdf_fn(digest)
        lambda do |chaining_key, input_key_material, num_output|
          hkdf(chaining_key, input_key_material, num_output, digest)
        end
      end

      def self.hkdf(chaining_key, input_key_material, num_outputs, digest)
        temp_key = hmac_hash(chaining_key, input_key_material, digest)
        output1 = hmac_hash(temp_key, "\x01", digest)
        output2 = hmac_hash(temp_key, output1 + "\x02", digest)
        return [output1, output2] if num_outputs == 2
        output3 = hmac_hash(temp_key, output2 + "\x03", digest)
        [output1, output2, output3]
      end
    end
  end
end
