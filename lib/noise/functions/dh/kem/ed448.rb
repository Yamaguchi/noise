# frozen_string_literal: true

module Noise
  module Functions
    module DH
      module Kem
        module ED448
          def generate_kem_keypair
            generate_keypair
          end

          def generate_kem_ciphertext(public_key)
            
          end

          def kem(key_pair, ciphertext)
            dh(ciphertext, key_pair.private_key)
          end
        end
      end
    end
  end
end
