# frozen_string_literal: true

module Noise
  module Transport
    # The IO a framed transport sits on, and the only place that deals with the ways a stream
    # differs from a message: it hands over fewer bytes than were asked for, takes fewer than it
    # was given, ends in the middle of something, or goes quiet.
    #
    # A transport holds one of these and asks it for whole frames. Like the transport above it,
    # one belongs to one thread: a stream has a position, and two threads reading it take halves
    # of each other's frames.
    class Stream
      # @param [IO] io the stream. Anything that answers #write and #readpartial will do, which is
      #   what makes a StringIO usable in a test.
      # @param [Numeric, nil] read_timeout how long to wait for the next bytes before giving up,
      #   in seconds. nil waits as long as the IO does. It applies to each wait rather than to a
      #   frame as a whole, so a peer that sends a byte at a time holds a read open without ever
      #   tripping it.
      # @raise [ArgumentError] if read_timeout is negative, or if the IO cannot be waited on and
      #   the timeout would therefore do nothing.
      def initialize(io, read_timeout: nil)
        validate_read_timeout!(io, read_timeout)

        @io = io
        @read_timeout = read_timeout
      end

      # Writes all of it, however many writes that takes.
      #
      # @param [String] frame the bytes to write.
      # @raise [IOError] if a write takes none of them, which would otherwise spin here forever.
      # @return [Integer] frame.bytesize, once all of it has gone out.
      def write(frame)
        written = 0
        while written < frame.bytesize
          taken = @io.write(frame.byteslice(written, frame.bytesize - written))
          raise IOError, "#{@io.class} took #{taken.inspect} of the #{frame.bytesize} bytes it was given." unless
            taken.is_a?(Integer) && taken.positive?

          written += taken
        end
        written
      end

      # @param [Integer] length how many bytes to read.
      # @raise [Noise::Exceptions::TruncatedMessageError] if the stream ends first.
      # @raise [Noise::Exceptions::ReadTimeoutError] if no more arrive in time.
      # @return [String] exactly length bytes.
      def read_exactly(length)
        gather(length) || truncated!(length, 0)
      end

      # The same, for the first bytes of a frame, where a stream that has ended has not been cut
      # short: it is the other party saying goodbye between one frame and the next.
      #
      # @param [Integer] length how many bytes to read.
      # @raise [Noise::Exceptions::TruncatedMessageError] if the stream ends after some of them.
      # @raise [Noise::Exceptions::ReadTimeoutError] if no more arrive in time.
      # @return [String, nil] exactly length bytes, or nil if the stream had already ended.
      def read_exactly_or_nil(length)
        gather(length)
      end

      private

      # @param [Integer] length how many bytes to read.
      # @raise [Noise::Exceptions::TruncatedMessageError] if the stream ends after some of them.
      # @return [String, nil] the bytes, or nil if the stream ended before any of them arrived.
      def gather(length)
        # Binary, because a frame is bytes: appending a chunk to a buffer of another encoding
        # would count characters where this counts bytes.
        buffer = ''.b
        while buffer.bytesize < length
          chunk = read_chunk(length - buffer.bytesize)
          return buffer.empty? ? nil : truncated!(length, buffer.bytesize) if chunk.nil?

          buffer << chunk
        end
        buffer
      end

      # @param [Integer] length how many bytes were needed.
      # @param [Integer] arrived how many turned up.
      # @raise [Noise::Exceptions::TruncatedMessageError] always.
      def truncated!(length, arrived)
        raise Noise::Exceptions::TruncatedMessageError,
              "Needed #{length} bytes, the stream ended after #{arrived}."
      end

      # Takes whatever has arrived, which on a socket is rarely a whole frame at once.
      #
      # @param [Integer] length the most to take.
      # @return [String, nil] the bytes, or nil at end of stream.
      def read_chunk(length)
        wait_readable
        @io.readpartial(length)
      rescue EOFError
        nil
      end

      # Asks the IO itself to wait, rather than selecting on its file descriptor, because bytes it
      # has already read and buffered are ready to be taken while the descriptor is quiet.
      #
      # @raise [Noise::Exceptions::ReadTimeoutError] if nothing arrives within read_timeout.
      # @return [void]
      def wait_readable
        return if @read_timeout.nil?
        return if @io.wait_readable(@read_timeout)

        raise Noise::Exceptions::ReadTimeoutError,
              "No more of the frame arrived within #{@read_timeout} seconds."
      end

      # @param [IO] io the stream this was given.
      # @param [Numeric, nil] read_timeout the timeout it was given.
      # @raise [ArgumentError] if the timeout could not be honoured as asked.
      # @return [void]
      def validate_read_timeout!(io, read_timeout)
        return if read_timeout.nil?

        raise ArgumentError, "read_timeout is #{read_timeout}, which is not a length of time." if read_timeout.negative?
        return if io.respond_to?(:wait_readable)

        raise ArgumentError,
              "read_timeout cannot be honoured on a #{io.class}, which does not answer #wait_readable. " \
              'Leave it out, or pass an IO that does.'
      end
    end
  end
end
