# frozen_string_literal: true

module Noise
  module Functions
    module DH
      # The 448 DH function of the Noise specification, which is X448 as defined by RFC 7748 and
      # not the Ed448 signature scheme the class name suggests. The name is kept because it is what
      # Protocol::DH maps '448' to and what callers reference.
      #
      # OpenSSL implements X448 and exposes it through the raw key interface, so this function needs
      # no gem and no system library beyond the OpenSSL that AesGcm and the HMAC helpers already use.
      class ED448
        DHLEN = 56

        # The name OpenSSL knows the curve by. Ed448 is a different algorithm, and asking for it
        # here would produce a signing key rather than one that can derive a shared secret.
        ALGORITHM = 'X448'

        def generate_keypair
          pkey = OpenSSL::PKey.generate_key(ALGORITHM)
          Noise::Key.new(pkey.raw_private_key, pkey.raw_public_key)
        end

        # Computes the X448 shared secret for the given remote public key.
        #
        # OpenSSL reports a public key it cannot use as OpenSSL::PKey::PKeyError, both when the key
        # is not DHLEN bytes and when the derivation would produce the all-zero output that RFC 7748
        # requires be rejected. Both are translated to InvalidPublicKeyError so that a caller
        # handling a peer-supplied key rescues the same class for every DH function. The local key
        # is built outside the rescue so that a malformed private key keeps propagating as
        # PKeyError instead of being reported as the peer's fault.
        def dh(private_key, public_key)
          raise Noise::Exceptions::InvalidPublicKeyError, public_key unless public_key.bytesize == DHLEN

          local = OpenSSL::PKey.new_raw_private_key(ALGORITHM, private_key)
          begin
            local.derive(OpenSSL::PKey.new_raw_public_key(ALGORITHM, public_key))
          rescue OpenSSL::PKey::PKeyError
            raise Noise::Exceptions::InvalidPublicKeyError, public_key
          end
        end

        def dhlen
          DHLEN
        end

        def self.from_private(private_key)
          pkey = OpenSSL::PKey.new_raw_private_key(ALGORITHM, private_key)
          Noise::Key.new(private_key, pkey.raw_public_key)
        end
      end
    end
  end
end
