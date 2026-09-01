# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'peer'
require_relative 'matrix'

Peer.require_binary!

# Runs a real handshake, and then a real transport exchange, between this gem and snow, the Rust
# implementation of the Noise Protocol Framework.
#
# The vectors in spec/vectors/ are replayed transcripts: both sides of every one of those tests
# are this gem reading a recording. They catch a wrong primitive, but a misreading of the
# specification that snow does not share goes unnoticed. These run the two implementations against
# each other over a pipe instead.
#
# This is deliberately outside `bundle exec rspec`, so that a contributor without a Rust toolchain
# can still run the suite. Run it with `bundle exec rake interop`.
RSpec.describe Noise::Connection do
  # Sets up both parties for one protocol and hands the block a connection and the harness.
  #
  # @param [String] protocol the Noise protocol name.
  # @param [Boolean] initiator whether this gem is the initiator.
  # @param [Symbol] transport what the harness does with each frame. See interop/src/main.rs.
  # @return [void]
  def session(protocol, initiator:, transport:)
    parsed = Noise::Protocol.create(protocol)
    pattern = parsed.pattern
    dh = parsed.dh_fn.class
    ours = dh.from_private(Interop::RUBY_STATIC)
    theirs = dh.from_private(Interop::PEER_STATIC)
    psk = Interop::PSK if pattern.psk_count.positive?

    we_need = pattern.required_keypairs(initiator)
    keypairs = {}
    keypairs[:s] = Interop::RUBY_STATIC if we_need.include?(:s)
    keypairs[:rs] = theirs.public_key if we_need.include?(:rs)

    peer = Peer.new(protocol: protocol, initiator: !initiator,
                    needs: pattern.required_keypairs(!initiator),
                    keys: { static: Interop::PEER_STATIC, remote: ours.public_key, psk: psk },
                    prologue: Interop::PROLOGUE, handshake_payload: Interop::HANDSHAKE_PAYLOAD,
                    transport: transport)

    role = initiator ? Noise::Connection::Initiator : Noise::Connection::Responder
    connection = role.new(protocol, keypairs: keypairs)
    connection.prologue = Interop::PROLOGUE
    connection.psks = [Interop::PSK] * pattern.psk_count if psk
    connection.start_handshake

    peer.run do |harness|
      handshake(connection, harness)
      yield connection, harness
    end
  end

  # Runs the handshake to the end, checking that every message the harness wrote carries the
  # payload it was told to send.
  #
  # @return [void]
  def handshake(connection, harness)
    until connection.handshake_finished?
      if connection.state == :handshake_write
        harness.write(connection.write_message(Interop::HANDSHAKE_PAYLOAD))
      else
        expect(connection.read_message(harness.read)).to eq Interop::HANDSHAKE_PAYLOAD
      end
    end
  end

  # This gem encrypts and the harness answers. In :echo it answers encrypted, which this gem then
  # decrypts; in :decrypt it answers in the clear, because a one-way pattern leaves it no key.
  #
  # @return [Array<String>] what came back for each payload sent.
  def send_payloads(protocol, initiator:, encrypted_reply:)
    answers = []
    session(protocol, initiator: initiator, transport: encrypted_reply ? :echo : :decrypt) do |connection, harness|
      Interop::PAYLOADS.each do |payload|
        harness.write(connection.encrypt(payload))
        answer = harness.read
        answers << (encrypted_reply ? connection.decrypt(answer) : answer)
        next unless payload == Interop::REKEY

        connection.rekey_encryption
        connection.rekey_decryption if encrypted_reply
      end
    end
    answers
  end

  # The harness encrypts and this gem decrypts, which is how a one-way pattern is covered in the
  # direction its responder can only listen in.
  #
  # @return [Array<String>] what this gem decrypted for each payload the harness was given.
  def receive_payloads(protocol)
    answers = []
    session(protocol, initiator: false, transport: :encrypt) do |connection, harness|
      Interop::PAYLOADS.each do |payload|
        harness.write(payload)
        answers << connection.decrypt(harness.read)
        connection.rekey_decryption if payload == Interop::REKEY
      end
    end
    answers
  end

  Interop.protocols.each do |protocol|
    describe protocol do
      one_way = Noise::Protocol.create(protocol).pattern.one_way?

      it 'runs a handshake and a transport exchange with this gem as the initiator' do
        expect(send_payloads(protocol, initiator: true, encrypted_reply: !one_way)).to eq Interop::PAYLOADS
      end

      if one_way
        # A one-way pattern gives its responder nothing to send, so the only exchange to run from
        # that side is the one where this gem decrypts what the harness encrypted.
        it 'decrypts what the other implementation sent, as the responder' do
          expect(receive_payloads(protocol)).to eq Interop::PAYLOADS
        end
      else
        it 'runs a handshake and a transport exchange with this gem as the responder' do
          expect(send_payloads(protocol, initiator: false, encrypted_reply: true)).to eq Interop::PAYLOADS
        end
      end
    end
  end
end
