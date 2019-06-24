# frozen_string_literal: true

module Noise
  module Connection
    class Responder < Base
      def initialize_next_message
        @next_message = :read
      end

      def initiator?
        false
      end

      def handshake_done(c1, c2)
        super
        @cipher_state_decrypt = c1
        @cipher_state_encrypt = @protocol.pattern.one_way? ? nil : c2
      end
    end
  end
end
