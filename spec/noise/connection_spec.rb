# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Connection do
  describe '#validate' do
    subject { connection.validate }

    let(:connection) { Noise::Connection.new(name, keypairs: keypairs) }
    let(:keypairs) { { s: nil, e: nil, rs: nil, re: nil } }

    context 'psk' do
      context 'valid' do
        let(:name) { 'Noise_KNpsk0+psk1_25519_AESGCM_SHA256' }
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

        before do
          connection.protocol.initiator = true
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
        before do
          connection.protocol.initiator = true
        end
        it { is_expected.to eq true }
      end

      context 'not initialized' do
        let(:keypairs) { { s: ('00' * 32).htb, e: nil, rs: nil, re: nil } }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoiseValidationError) }
      end

      context 'unmatch key pair' do
        let(:keypairs) { { s: nil, e: ('00' * 32).htb, rs: nil, re: nil } }

        it { expect { subject }.to raise_error(Noise::Exceptions::NoiseValidationError) }
      end
    end
  end
end
