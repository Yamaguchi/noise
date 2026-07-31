# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Connection do
  describe '#validate' do
    subject { connection.validate }

    let(:connection) { Noise::Connection::Initiator.new(name, keypairs: keypairs) }
    let(:keypairs) { { s: nil, e: nil, rs: nil, re: nil } }

    context 'psk' do
      context 'valid' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

        before do
          connection.psks = [('00' * 32).htb, ('00' * 32).htb]
        end
        it { is_expected.to eq true }
      end

      context 'too long psk' do
        let(:name) { 'Noise_KNpsk0_25519_AESGCM_SHA256' }
        before { connection.psks = [('00' * 33).htb] }
        it { expect { subject }.to raise_error(Noise::Exceptions::NoisePSKError) }
      end

      context 'unmatch psk type' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }
        before { connection.psks = [('00' * 32).htb] }
        it { expect { subject }.to raise_error(Noise::Exceptions::NoisePSKError) }
      end
    end

    context 'non-psk' do
      let(:name) { 'Noise_KN_25519_AESGCM_SHA256' }
      let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

      context 'valid' do
        it { is_expected.to eq true }
      end

      context 'unmatch key pair' do
        let(:keypairs) { { s: nil, e: ('00' * 32).htb, rs: nil, re: nil } }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoiseValidationError) }
      end
    end
  end

  describe 'one-way pattern' do
    let(:name) { 'Noise_N_25519_AESGCM_SHA256' }
    let(:responder_key) { Noise::Functions::DH::ED25519.new.generate_keypair }
    let(:initiator) { Noise::Connection::Initiator.new(name, keypairs: { rs: responder_key.public_key }) }
    let(:responder) { Noise::Connection::Responder.new(name, keypairs: { s: responder_key.private_key }) }

    before do
      initiator.start_handshake
      responder.start_handshake
      responder.read_message(initiator.write_message)
    end

    it 'lets the initiator send transport messages' do
      expect(responder.decrypt(initiator.encrypt('hello'))).to eq 'hello'
    end

    it 'rejects a send by the responder' do
      expect { responder.encrypt('hello') }.to raise_error(
        Noise::Exceptions::NoiseHandshakeError, Noise::Connection::Base::ONE_WAY_SEND_ERROR
      )
    end

    it 'rejects a receive by the initiator' do
      expect { initiator.decrypt('hello') }.to raise_error(
        Noise::Exceptions::NoiseHandshakeError, Noise::Connection::Base::ONE_WAY_RECEIVE_ERROR
      )
    end
  end
end
