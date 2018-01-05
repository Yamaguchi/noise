# frozen_string_literal: true

require 'spec_helper'

require 'json'
require 'pp'

RSpec.describe 'Vectors' do
  def to_keypair_value(enum, v, role)
    key =
      case enum
      when Noise::KeyPair::STATIC then (role + '_static').to_sym
      when Noise::KeyPair::EPHEMERAL then (role + '_ephemeral').to_sym
      when Noise::KeyPair::REMOTE_STATIC then (role + '_remote_static').to_sym
      end
    v[key]
  end

  def set_keypairs(v, conn)
    role = conn.protocol.initiator ? 'init' : 'resp'
    value = to_keypair_value(Noise::KeyPair::STATIC, v, role)
    conn.set_keypair_from_private(Noise::KeyPair::STATIC, value.htb) if value

    value = to_keypair_value(Noise::KeyPair::EPHEMERAL, v, role)
    conn.set_keypair_from_private(Noise::KeyPair::EPHEMERAL, value.htb) if value

    value = to_keypair_value(Noise::KeyPair::REMOTE_STATIC, v, role)
    conn.set_keypair_from_public(Noise::KeyPair::REMOTE_STATIC, value.htb) if value
  end

  files = ['cacophony.txt', 'snow-multipsk.txt', 'lightning.txt']
  vectors =
    files.flat_map do |file|
      path = "#{File.dirname(__FILE__)}/vectors/#{file}"
      JSON.parse(File.read(path), symbolize_names: true)
    end

  it { expect(vectors).not_to be_nil }

  describe 'test_vectors' do
    vectors.each do |v|
      next if v[:protocol_name].include?('BLAKE2s')
      next if v[:protocol_name].include?('448')

      context "test-vector #{v[:protocol_name]}" do
        it do
          initiator = Noise::Connection.new(v[:protocol_name])
          responder = Noise::Connection.new(v[:protocol_name])
          if v.key?(:init_psks) && v.key?(:resp_psks)
            initiator.psks = v[:init_psks]
            responder.psks = v[:resp_psks]
            next
          end

          initiator.prologue = v[:init_prologue].htb
          initiator.set_as_initiator!
          set_keypairs(v, initiator)

          responder.prologue = v[:resp_prologue].htb
          responder.set_as_responder!
          set_keypairs(v, responder)

          initiator.start_handshake
          responder.start_handshake

          initiator_to_responder = true
          handshake_finished = false
          v[:messages].each do |message|
            if handshake_finished
              if message[:payload] && message[:ciphertext]
                one_way_or_initiator = initiator.protocol.pattern.one_way || initiator_to_responder
                sender = one_way_or_initiator ? initiator : responder
                receiver = one_way_or_initiator ? responder : initiator

                ciphertext = sender.encrypt(message[:payload].htb)
                expect(ciphertext.bth).to eq message[:ciphertext]
                plaintext = receiver.decrypt(message[:ciphertext].htb)
                expect(plaintext.bth).to eq message[:payload]
              end
            else
              sender = initiator_to_responder ? initiator : responder
              receiver = initiator_to_responder ? responder : initiator
              ciphertext = sender.write_message(message[:payload].htb)
              expect(ciphertext.bth).to eq message[:ciphertext]

              plaintext = receiver.read_message(message[:ciphertext].htb)
              expect(plaintext.bth).to eq message[:payload]
              if sender.handshake_finished && receiver.handshake_finished
                handshake_finished = true
                if v.key?(:handshake_hash)
                  expect(initiator.protocol.handshake_hash.bth).to eq v[:handshake_hash]
                  expect(responder.protocol.handshake_hash.bth).to eq v[:handshake_hash]
                end
                expect(initiator.protocol.cipher_state_encrypt.k).to eq responder.protocol.cipher_state_decrypt.k

                if initiator.protocol.pattern.one_way
                  expect(initiator.protocol.cipher_state_decrypt).to be_nil
                  expect(responder.protocol.cipher_state_encrypt).to be_nil
                else
                  expect(initiator.protocol.cipher_state_decrypt.k).to eq responder.protocol.cipher_state_encrypt.k
                end
              else
                expect(sender.handshake_finished).to eq receiver.handshake_finished
              end
            end
            initiator_to_responder = !initiator_to_responder
          end
        end
      end
    end
  end
end
