# frozen_string_literal: true

module Noise
  module Connection
    autoload :Base, 'noise/connection/base'
    autoload :Initiator, 'noise/connection/initiator'
    autoload :Responder, 'noise/connection/responder'
  end
end
