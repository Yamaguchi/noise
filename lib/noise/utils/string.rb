# frozen_string_literal: true

module Noise
  module Utils
    # Hex conversion helpers. Offered as a refinement so that requiring this gem does not add methods
    # to String for the whole process.
    #
    #   using Noise::Utils::HexString
    #   '0102'.htb     # => "\x01\x02"
    #   "\x01\x02".bth # => "0102"
    module HexString
      refine ::String do
        # hex to binary
        def htb
          [self].pack('H*')
        end

        # binary to hex
        def bth
          unpack1('H*')
        end
      end
    end
  end
end
