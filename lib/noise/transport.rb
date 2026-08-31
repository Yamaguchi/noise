# frozen_string_literal: true

module Noise
  # The layers that put a Noise::Connection on top of an IO. A connection encrypts and decrypts
  # whole messages, which is the shape the Noise specification describes but not the shape a
  # socket has, so something has to say where one message ends and the next begins.
  module Transport
    autoload :Framed, 'noise/transport/framed'
  end
end
