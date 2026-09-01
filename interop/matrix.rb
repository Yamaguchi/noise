# frozen_string_literal: true

# What the interoperability suite runs, and the keys it runs with.
module Interop
  # Fixed keys, so that a failure can be reproduced from the output alone.
  RUBY_STATIC = ("\x11" * 32).b
  PEER_STATIC = ("\x22" * 32).b
  PSK = ("\x33" * 32).b
  PROLOGUE = 'interoperability'

  # Carried by every handshake message in both directions, and checked by both sides, so that the
  # payload each implementation encrypts into a handshake message is covered too.
  HANDSHAKE_PAYLOAD = 'handshake'

  # Answering this payload also makes both parties rekey, which is how the transport phase's rekey
  # is exercised across the two implementations.
  REKEY = '__rekey__'

  # One pattern per family, plus the modifiers this gem and snow both implement. N, K and X are
  # the one-way family; the twelve after them are the interactive fundamentals; NNpsk0 and XXpsk3
  # place a psk at each end of a handshake; K1X1 is a deferred pattern.
  PATTERNS = %w[N K X NN NK NX KN KK KX XN XK XX IN IK IX NNpsk0 XXpsk3 K1X1].freeze

  # Every cipher this gem implements, against every hash the two have in common. snow has neither
  # 448 nor secp256k1, so 25519 is the only DH function the two can share.
  SUITES = [
    'ChaChaPoly_SHA256', 'AESGCM_SHA256', 'ChaChaPoly_SHA512',
    'AESGCM_BLAKE2s', 'ChaChaPoly_BLAKE2b'
  ].freeze

  # A zero-length payload and the longest one a Noise message can carry are where a framing goes
  # wrong; the rekey in the middle makes both sides replace their transport keys and carry on.
  PAYLOADS = [
    'hello', '', 'a' * 1000, 'b' * Noise::Connection::Base::MAX_PLAINTEXT_LENGTH,
    REKEY, 'after the rekey'
  ].freeze

  # @return [Array<String>] every protocol name the suite runs.
  def self.protocols
    PATTERNS.flat_map { |pattern| SUITES.map { |suite| "Noise_#{pattern}_25519_#{suite}" } }
  end
end
