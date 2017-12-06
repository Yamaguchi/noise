# frozen_string_literal: true

require 'spec_helper'

require 'json'
require 'pp'

RSpec.describe 'Vectors' do
  def set_keypairs(v, conn)
    role = conn.protocol.initiator ? 'init' : 'resp'
    key = (role + '_static').to_sym
    conn.set_keypair_from_private(Noise::KeyPair::STATIC, v[key].htb) if v[key]

    key = (role + '_ephemeral').to_sym
    conn.set_keypair_from_private(Noise::KeyPair::EPHEMERAL, v[key].htb) if v[key]

    key = (role + '_remote_static').to_sym
    conn.set_keypair_from_public(Noise::KeyPair::REMOTE_STATIC, v[key].htb) if v[key]
  end

  files = ['cacophony.txt', 'snow-multipsk.txt']

  vectors =
    files.flat_map do |file|
      path = "#{File.dirname(__FILE__)}/vectors/#{file}"
      JSON.parse(File.read(path), symbolize_names: true)
    end

  it { expect(vectors).not_to be_nil }

  describe 'test_vectors' do
    vectors.each do |v|
      next if v[:protocol_name].include?('BLAKE')
      next if v[:protocol_name].include?('448')
      next if v[:protocol_name].include?('AES')
      next if v[:protocol_name].include?('psk')
      # next if v[:protocol_name] != 'Noise_NN_25519_ChaChaPoly_SHA256'
      # next if v[:protocol_name] != 'Noise_IK_25519_ChaChaPoly_SHA256'

      context "test-vector #{v[:protocol_name]}" do
        it do
          initiator = Noise::Connection.new(v[:protocol_name])
          responder = Noise::Connection.new(v[:protocol_name])
          if v.key?(:init_psks) && v.key?(:resp_psks)
            # TODO : PSK Mode support
            # initiator.psks = v[:init_psks]
            # responder.psks = v[:resp_psks]
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
              one_way_or_initiator = initiator.protocol.pattern.one_way || initiator_to_responder
              sender = one_way_or_initiator ? initiator : responder
              receiver = one_way_or_initiator ? responder : initiator

              ciphertext = sender.encrypt(message[:payload].htb)
              expect(ciphertext.bth).to eq message[:ciphertext]
              plaintext = receiver.decrypt(message[:ciphertext].htb)
              expect(plaintext.bth).to eq message[:payload]

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
