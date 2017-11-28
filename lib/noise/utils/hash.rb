# frozen_string_literal: true

class Hash
  def stringify_keys
    keys.each_with_object({}) do |key, h|
      h[key.to_s] = self[key]
    end
  end
end
