# frozen_string_literal: true

module Noise
  # The layers that put a Noise::Connection on top of an IO. A connection encrypts and decrypts
  # whole messages, which is the shape the Noise specification describes but not the shape a
  # socket has, so something has to say where one message ends and the next begins.
  # Stream is not one of those layers but the thing they stand on: the IO, and the ways a stream
  # differs from a message.
  module Transport
    autoload :Bolt8, 'noise/transport/bolt8'
    autoload :Framed, 'noise/transport/framed'
    autoload :Stream, 'noise/transport/stream'
  end
end
