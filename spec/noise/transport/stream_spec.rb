# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

RSpec.describe Noise::Transport::Stream do
  describe '.new' do
    it 'refuses a negative read timeout' do
      expect { described_class.new(StringIO.new, read_timeout: -1) }
        .to raise_error(ArgumentError, 'read_timeout is -1, which is not a length of time.')
    end

    # A timeout that cannot be honoured is worse than none, because nothing reports that it was
    # dropped and the read blocks for as long as the peer stays silent.
    it 'refuses a read timeout on a stream that cannot be waited on' do
      expect { described_class.new(StringIO.new, read_timeout: 1) }
        .to raise_error(ArgumentError, /StringIO, which does not answer #wait_readable/)
    end

    it 'takes a stream that cannot be waited on when no timeout is asked for' do
      expect { described_class.new(StringIO.new) }.not_to raise_error
    end
  end

  describe '#write' do
    it 'keeps writing until every byte has gone out, in order' do
      io = ChunkedIO.new(chunk: 7)

      expect(described_class.new(io).write('a longer message than one chunk')).to eq 31
      expect(io.written).to eq 'a longer message than one chunk'
    end

    it 'reports a stream that takes none of the bytes it is given' do
      expect { described_class.new(ChunkedIO.new(chunk: 0)).write('hello') }
        .to raise_error(IOError, 'ChunkedIO took 0 of the 5 bytes it was given.')
    end
  end

  describe '#read_exactly' do
    it 'answers exactly the bytes asked for, leaving the rest' do
      stream = described_class.new(StringIO.new('abcdef'))

      expect(stream.read_exactly(2)).to eq 'ab'
      expect(stream.read_exactly(4)).to eq 'cdef'
    end

    it 'reassembles what arrives a byte at a time' do
      expect(described_class.new(ChunkedIO.new(data: 'abcdef', chunk: 1)).read_exactly(6)).to eq 'abcdef'
    end

    it 'reports a stream that ends part way through' do
      expect { described_class.new(StringIO.new('abc')).read_exactly(6) }
        .to raise_error(Noise::Exceptions::TruncatedMessageError, 'Needed 6 bytes, the stream ended after 3.')
    end

    it 'reports a stream that had already ended' do
      expect { described_class.new(StringIO.new('')).read_exactly(6) }
        .to raise_error(Noise::Exceptions::TruncatedMessageError, 'Needed 6 bytes, the stream ended after 0.')
    end
  end

  describe '#read_exactly_or_nil' do
    it 'answers the bytes when they are there' do
      expect(described_class.new(StringIO.new('abcdef')).read_exactly_or_nil(6)).to eq 'abcdef'
    end

    it 'answers nil when the stream had already ended' do
      expect(described_class.new(StringIO.new('')).read_exactly_or_nil(6)).to be_nil
    end

    # Ending between frames is a goodbye; ending inside one is not.
    it 'still reports a stream that ends part way through' do
      expect { described_class.new(StringIO.new('abc')).read_exactly_or_nil(6) }
        .to raise_error(Noise::Exceptions::TruncatedMessageError, 'Needed 6 bytes, the stream ended after 3.')
    end
  end

  describe 'read_timeout' do
    it 'gives up when the rest does not arrive' do
      reader, writer = IO.pipe
      writer.write('ab')

      expect { described_class.new(reader, read_timeout: 0.05).read_exactly(6) }
        .to raise_error(Noise::Exceptions::ReadTimeoutError, 'No more of the frame arrived within 0.05 seconds.')
    ensure
      [reader, writer].each(&:close)
    end

    it 'answers the bytes that are already there' do
      reader, writer = IO.pipe
      writer.write('abcdef')

      expect(described_class.new(reader, read_timeout: 5).read_exactly(6)).to eq 'abcdef'
    ensure
      [reader, writer].each(&:close)
    end

    it 'waits as long as the stream does when none is asked for' do
      reader, writer = IO.pipe
      writer.write('abcdef')
      writer.close

      expect(described_class.new(reader).read_exactly(6)).to eq 'abcdef'
    ensure
      reader.close
    end
  end
end
