# frozen_string_literal: true

require 'open3'

# The snow process on the other side of a handshake, and the framing the two speak over its stdin
# and stdout: each Noise message preceded by its length as two big-endian bytes.
#
# The harness is told which protocol to run and which keys to hold, so that both parties are
# configured from here and the test knows every key in play.
#
# Every read has a deadline. A gem and a reference implementation that disagree about how many
# handshake messages a pattern has, or about whose turn it is, leave both sides waiting for the
# other, and that disagreement is among the most valuable things this suite exists to find. It has
# to arrive as a failure rather than as a suite that never finishes.
class Peer
  # Where the harness binary lands. `cargo build --release` puts it here.
  BINARY = File.expand_path('target/release/noise-interop', __dir__)

  # How long to wait for the harness to answer. A whole session takes single-digit milliseconds,
  # so this is only ever reached when something is stuck.
  READ_TIMEOUT = 10

  class << self
    # @raise [RuntimeError] if the harness has not been built.
    # @return [void]
    def require_binary!
      return if File.executable?(BINARY)

      raise "#{BINARY} is missing. Build it with: cd interop && cargo build --release"
    end
  end

  # @param [String] protocol the Noise protocol name both parties run.
  # @param [Boolean] initiator whether the harness is the initiator, which is the opposite of what
  #   the Ruby side is.
  # @param [Array<Symbol>] needs the keys the pattern asks this party for, from
  #   Noise::Pattern#required_keypairs.
  # @param [Hash] keys :static is this party's private key, :remote the other party's public key,
  #   and :psk the pre-shared key when the pattern has one.
  # @param [String] prologue the prologue both parties mix in.
  # @param [String] handshake_payload what every handshake message carries, in both directions.
  # @param [Symbol] transport :echo, :decrypt or :encrypt. See interop/src/main.rs.
  def initialize(protocol:, initiator:, needs:, keys:, prologue:, handshake_payload:, transport:)
    @arguments = ['--protocol', protocol,
                  '--role', initiator ? 'initiator' : 'responder',
                  '--prologue', hex(prologue),
                  '--handshake-payload', hex(handshake_payload),
                  '--transport', transport.to_s]
    @arguments += ['--local-static', hex(keys[:static])] if needs.include?(:s)
    @arguments += ['--remote-static', hex(keys[:remote])] if needs.include?(:rs)
    @arguments += ['--psk', hex(keys[:psk])] if keys[:psk]
  end

  # Starts the harness and hands itself to the block, which drives the exchange through #write and
  # #read. The process is closed down when the block returns, and anything it printed to stderr is
  # carried into whatever failure comes out, since that is where snow explains itself.
  #
  # @raise [RuntimeError] if the harness fails, stops answering, or is killed.
  # @return [void]
  def run
    Open3.popen3(BINARY, *@arguments) do |stdin, stdout, stderr, thread|
      @stdin = stdin.tap(&:binmode)
      @stdout = stdout.tap(&:binmode)
      # Read stderr on its own thread: a harness that fills the pipe would otherwise stop, and a
      # harness that panics has to be able to say why even when the Ruby side is not reading.
      complaints = Thread.new { stderr.read }

      begin
        yield self
        @stdin.close
        status = thread.value
        raise "the harness exited with #{status.exitstatus}" unless status.success?
      rescue StandardError => e
        Process.kill('KILL', thread.pid) if thread.alive?
        raise "#{e.message}\n#{complaints.value}"
      end
    end
  end

  # @param [String] frame the message to send.
  # @return [void]
  def write(frame)
    @stdin.write([frame.bytesize].pack('n') + frame)
    @stdin.flush
  end

  # @raise [RuntimeError] if the harness stops answering or sends less than it announced.
  # @return [String] one message.
  def read
    read_exactly(read_exactly(2).unpack1('n'))
  end

  private

  # Framed by hand rather than through Noise::Transport::Stream: a test of this gem should not
  # depend on the gem to tell it what arrived.
  #
  # @param [Integer] length how many bytes to read.
  # @raise [RuntimeError] if they do not all arrive in time.
  # @return [String] exactly length bytes.
  def read_exactly(length)
    buffer = ''.b
    while buffer.bytesize < length
      raise "the harness sent nothing for #{READ_TIMEOUT} seconds" unless @stdout.wait_readable(READ_TIMEOUT)

      chunk = begin
        @stdout.readpartial(length - buffer.bytesize)
      rescue EOFError
        raise "the harness closed after #{buffer.bytesize} of the #{length} bytes it owed"
      end
      buffer << chunk
    end
    buffer
  end

  def hex(bytes) = bytes.unpack1('H*')
end
