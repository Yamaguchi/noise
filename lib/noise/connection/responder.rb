# frozen_string_literal: true

module Noise
  module Connection
    class Responder < Base
      # The responder reads the first handshake message of the pattern.
      #
      # @return [Symbol] the state start_handshake moves this party into.
      def initial_turn
        :handshake_read
      end

      def initiator?
        false
      end

      def handshake_done(c1, c2)
        super
        @cipher_state_decrypt = c1
        @cipher_state_encrypt = other_direction_cipher_state(c1, c2)
      end
    end
  end
end
