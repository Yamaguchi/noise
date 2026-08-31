# frozen_string_literal: true

# A stream that hands out at most `chunk` bytes per readpartial and takes at most `chunk` bytes
# per write, so that the partial reads and partial writes a socket produces can be exercised
# without opening one.
class ChunkedIO
  attr_reader :written

  # @param [String] data what the stream holds to be read.
  # @param [Integer] chunk the most to move in one call.
  def initialize(data: '', chunk: 1)
    @data = data.b
    @chunk = chunk
    @written = ''.b
    @position = 0
  end

  # @param [Integer] length the most to take.
  # @raise [EOFError] once the data has run out, as an IO does.
  # @return [String] at most chunk bytes.
  def readpartial(length)
    raise EOFError if @position >= @data.bytesize

    taken = @data.byteslice(@position, [length, @chunk].min)
    @position += taken.bytesize
    taken
  end

  # @param [String] bytes what to write.
  # @return [Integer] how many of them were taken, which is at most chunk. A chunk of zero stands
  #   for a stream that takes nothing, which a real IO does not do.
  def write(bytes)
    taken = bytes.byteslice(0, @chunk)
    @written << taken
    taken.bytesize
  end
end
