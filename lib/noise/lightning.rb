# frozen_string_literal: true

module Noise
  # The transport layer BOLT #8 builds on top of a Noise connection, for the Lightning Network.
  #
  # Nothing else in this gem depends on it, and requiring 'noise' does not load it until something
  # names Noise::Lightning.
  module Lightning
    autoload :Transport, 'noise/lightning/transport'
  end
end
