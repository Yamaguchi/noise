# frozen_string_literal: true

module Noise
  class Key
    attr_reader :private_key, :public_key

    def initialize(private_key, public_key)
      @private_key = private_key
      @public_key = public_key
    end
  end
end
