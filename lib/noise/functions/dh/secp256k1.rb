# frozen_string_literal: true

module Noise
  module Functions
    module DH
      # The secp256k1 DH function, as the Lightning Network uses it in BOLT #8.
      #
      # The shared secret is SHA256 of the shared point in compressed form, not the raw X
      # coordinate. That is what BOLT #8 specifies and what libsecp256k1's ecdh returned when this
      # function was backed by that library, so the value on the wire is unchanged.
      class Secp256k1
        # Length of a compressed secp256k1 point. The 65-byte uncompressed form encodes the same
        # point, but Noise exchanges only the compressed one, so it is rejected.
        DHLEN = 33

        # Length of a secp256k1 scalar, which is what a private key is.
        PRIVATE_KEY_LEN = 32

        # The name OpenSSL knows the curve by.
        CURVE = 'secp256k1'

        # Builds the curve group once, because dh needs it on every call.
        #
        # secp256k1 is a builtin curve of OpenSSL 3, but an OpenSSL restricted to a FIPS provider
        # does not offer it. That leaves the function unusable in the same way a missing system
        # library did, so it is reported as MissingDependencyError rather than as an OpenSSL error
        # raised in the middle of a handshake.
        def initialize
          @group = OpenSSL::PKey::EC::Group.new(CURVE)
        rescue OpenSSL::PKey::EC::Group::Error => e
          raise Noise::Exceptions::MissingDependencyError,
                "OpenSSL does not offer the #{CURVE} curve: #{e.message}"
        end

        def generate_keypair
          group = ECDSA::Group::Secp256k1
          private_key = 1 + SecureRandom.random_number(group.order - 1)
          public_key = group.generator.multiply_by_scalar(private_key)
          Noise::Key.new(
            ECDSA::Format::IntegerOctetString.encode(private_key, PRIVATE_KEY_LEN),
            ECDSA::Format::PointOctetString.encode(public_key, compression: true)
          )
        end

        # Computes the ECDH shared secret for the given remote public key.
        #
        # Every way a peer-supplied key can be unusable raises InvalidPublicKeyError, matching the
        # other DH functions: a length other than DHLEN, and an encoding that names no point on the
        # curve. A private key the caller owns is not the peer's fault, so a malformed one raises
        # ArgumentError instead, as it did when the gem parsed it.
        def dh(private_key, public_key)
          raise Noise::Exceptions::InvalidPublicKeyError, public_key unless public_key.bytesize == DHLEN

          scalar = private_key_scalar(private_key)
          shared = parse_public_key(public_key).mul(scalar)
          # A backstop rather than a reachable case: secp256k1 has cofactor 1, so a point that
          # parsed has order n, and the scalar is already known to be in [1, n-1]. It stays because
          # the cost is one comparison and the failure it guards is severe - the compressed
          # encoding of infinity is the single byte 0x00, whose SHA256 anyone can precompute.
          raise Noise::Exceptions::InvalidPublicKeyError, public_key if shared.infinity?

          OpenSSL::Digest.digest('SHA256', shared.to_octet_string(:compressed))
        end

        def dhlen
          DHLEN
        end

        def self.from_private(private_key)
          group = ECDSA::Group::Secp256k1
          scalar = ECDSA::Format::IntegerOctetString.decode(private_key)
          point = group.generator.multiply_by_scalar(scalar)
          Noise::Key.new(private_key, ECDSA::Format::PointOctetString.encode(point, compression: true))
        end

        private

        # Decodes a public key into a point on the curve.
        #
        # The key is passed as a String, not as an OpenSSL::BN. OpenSSL then decodes it as an octet
        # string and raises Point::Error for anything that is not a point on the curve, the
        # all-zero key included: 0x00 introduces the encoding of infinity, which is one byte long,
        # so 33 zero bytes are rejected as a malformed encoding. Handing over a BN instead would
        # drop the leading zero byte and produce the point at infinity, whose shared secret is a
        # constant that the sender of such a key could precompute.
        def parse_public_key(public_key)
          OpenSSL::PKey::EC::Point.new(@group, public_key)
        rescue OpenSSL::PKey::EC::Point::Error
          raise Noise::Exceptions::InvalidPublicKeyError, public_key
        end

        # Decodes a private key into a scalar the curve accepts.
        #
        # A scalar of zero, or one that is a multiple of the group order, multiplies every point to
        # infinity. Rejecting it here keeps that case from being reported as the peer's invalid
        # public key.
        def private_key_scalar(private_key)
          unless private_key.bytesize == PRIVATE_KEY_LEN
            raise ArgumentError, "private key must be #{PRIVATE_KEY_LEN} bytes"
          end

          scalar = OpenSSL::BN.new(private_key, 2)
          raise ArgumentError, 'private key is out of range' if scalar <= 0 || scalar >= @group.order

          scalar
        end
      end
    end
  end
end
