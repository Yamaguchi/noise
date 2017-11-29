# frozen_string_literal: true

class String
  def htb
    [self].pack("H*")
  end
  def bth
    self.unpack("H*").first
  end
end
