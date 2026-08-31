# frozen_string_literal: true

module Noise
  module Connection
    class Initiator < Base
      # The initiator writes the first handshake message of the pattern.
      #
      # @return [Symbol] the state start_handshake moves this party into.
      def initial_turn
        :handshake_write
      end

      def initiator?
        true
      end

      def handshake_done(c1, c2)
        super
        @cipher_state_encrypt = c1
        @cipher_state_decrypt = @protocol.pattern.one_way? ? nil : c2
      end
    end
  end
end
