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

  def get_keypairs(v, initiator)
    keypairs = { s: nil, e: nil, rs: nil, re: nil }
    role = initiator ? 'init' : 'resp'
    value = to_keypair_value(Noise::KeyPair::STATIC, v, role)
    keypairs[Noise::KeyPair::STATIC.to_sym] = value.htb if value

    value = to_keypair_value(Noise::KeyPair::EPHEMERAL, v, role)
    keypairs[Noise::KeyPair::EPHEMERAL.to_sym] = value.htb if value

    value = to_keypair_value(Noise::KeyPair::REMOTE_STATIC, v, role)
    keypairs[Noise::KeyPair::REMOTE_STATIC.to_sym] = value.htb if value
    keypairs
  end

  files = ['cacophony.txt', 'snow.txt', 'lightning.txt', 'noise-c-basic.txt', 'noise-c-fallback.txt', 'noise-c-hybrid.txt']
  vectors =
    files.flat_map do |file|
      path = "#{File.dirname(__FILE__)}/vectors/#{file}"
      JSON.parse(File.read(path), symbolize_names: true)[:vectors]
    end

  it { expect(vectors).not_to be_nil }

  describe 'test_vectors' do
    vectors.each do |v|
      protocol_name = v[:name] || v[:protocol_name]
      next if protocol_name.include?('448')
      next if protocol_name.include?('NoisePSK')

      context "test-vector #{protocol_name}" do
        it do
          keypairs = get_keypairs(v, true)
          initiator = Noise::Connection::Initiator.new(protocol_name, keypairs: keypairs)
          keypairs = get_keypairs(v, false)
          responder = Noise::Connection::Responder.new(protocol_name, keypairs: keypairs)
          if v.key?(:init_psks) && v.key?(:resp_psks)
            initiator.psks = v[:init_psks].map(&:htb)
            responder.psks = v[:resp_psks].map(&:htb)
          end

          initiator.prologue = v[:init_prologue].htb
          responder.prologue = v[:resp_prologue].htb

          initiator.start_handshake
          responder.start_handshake

          initiator_to_responder = true
          handshake_finished = false
          v[:messages].each do |message|
            if handshake_finished
              if message[:payload] && message[:ciphertext]
                one_way_or_initiator = initiator.protocol.pattern.one_way? || initiator_to_responder
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

              sender_message_len = sender.handshake_state.expected_message_length(message[:payload].htb.bytesize)
              expect(sender_message_len).to eq message[:ciphertext].htb.bytesize

              ciphertext = sender.write_message(message[:payload].htb)
              expect(ciphertext.bth).to eq message[:ciphertext]

              receiver_message_len = receiver.handshake_state.expected_message_length(message[:payload].htb.bytesize)
              expect(receiver_message_len).to eq message[:ciphertext].htb.bytesize

              plaintext = receiver.read_message(message[:ciphertext].htb)
              expect(plaintext.bth).to eq message[:payload]

              if sender.handshake_finished && receiver.handshake_finished
                handshake_finished = true
                if v.key?(:handshake_hash)
                  expect(initiator.handshake_hash.bth).to eq v[:handshake_hash]
                  expect(responder.handshake_hash.bth).to eq v[:handshake_hash]
                end
                expect(initiator.cipher_state_encrypt.k).to eq responder.cipher_state_decrypt.k

                if initiator.protocol.pattern.one_way?
                  expect(initiator.cipher_state_decrypt).to be_nil
                  expect(responder.cipher_state_encrypt).to be_nil
                else
                  expect(initiator.cipher_state_decrypt.k).to eq responder.cipher_state_encrypt.k
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
