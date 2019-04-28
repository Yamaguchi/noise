# frozen_string_literal: true

module Noise
  module Connection
    class Initiator < Base
      def initialize(name, keypairs: { s: nil, e: nil, rs: nil, re: nil })
        super
        @next_message = :write
      end

      def initiator?
        true
      end

      def handshake_done(c1, c2)
        super
        @cipher_state_encrypt = c1

        if @protocol.pattern.one_way
          @cipher_state_decrypt = nil
        else
          @cipher_state_decrypt = c2
        end
      end
    end
  end
end
