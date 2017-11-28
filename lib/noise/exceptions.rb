# frozen_string_literal: true

module Noise
  module Exceptions
    autoload :MaxNonceError, 'noise/exceptions/max_nonce_error'
    autoload :ProtocolNameError, 'noise/exceptions/protocol_name_error'
  end
end
