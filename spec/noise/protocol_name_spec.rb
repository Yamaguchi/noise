# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::ProtocolName do
  describe '.parse' do
    subject(:parsed) { described_class.parse(name) }

    context 'a name without modifiers' do
      let(:name) { 'Noise_XX_25519_ChaChaPoly_SHA256' }

      it 'splits the name into its five parts' do
        expect(parsed.name).to eq name
        expect(parsed.pattern_name).to eq 'XX'
        expect(parsed.modifiers).to eq []
        expect(parsed.dh_names).to eq ['25519']
        expect(parsed.cipher_name).to eq 'ChaChaPoly'
        expect(parsed.hash_name).to eq 'SHA256'
      end

      it { expect(parsed.to_s).to eq name }
    end

    context 'a deferred pattern, whose name contains a digit' do
      let(:name) { 'Noise_X1K1_25519_AESGCM_SHA256' }

      it { expect(parsed.pattern_name).to eq 'X1K1' }
      it { expect(parsed.modifiers).to eq [] }
    end

    context 'a name with one modifier' do
      let(:name) { 'Noise_NNpsk0_25519_AESGCM_SHA256' }

      it { expect(parsed.pattern_name).to eq 'NN' }

      it 'parses the modifier written after the pattern name' do
        expect(parsed.modifiers.size).to eq 1
        expect(parsed.modifiers.first).to be_a Noise::Modifier::Psk
        expect(parsed.modifiers.first.index).to eq 0
      end
    end

    context 'a name with several modifiers' do
      let(:name) { 'Noise_NNpsk0+psk1_25519_AESGCM_SHA256' }

      it 'keeps them in the order the name writes them' do
        expect(parsed.modifiers.map(&:index)).to eq [0, 1]
      end
    end

    context 'a name whose modifier is not a psk' do
      let(:name) { 'Noise_XXfallback_25519_AESGCM_SHA256' }

      it { expect(parsed.pattern_name).to eq 'XX' }
      it { expect(parsed.modifiers.first).to be_a Noise::Modifier::Fallback }
    end

    # This is how a hybrid handshake names two DH functions at once. Nothing in this gem runs one
    # yet, but the name of one parses, so that Protocol is the only place that has to say so.
    context 'a hybrid DH name' do
      let(:name) { 'Noise_NN_25519+448_ChaChaPoly_BLAKE2s' }

      it { expect(parsed.dh_names).to eq %w[25519 448] }
    end

    context 'a malformed name' do
      # Every one of these is reported the same way, from the same place.
      {
        'too few parts' => 'Noise_NN_25519_AESGCM',
        'too many parts' => 'Noise_NN_25519_AESGCM_SHA256_EXTRA',
        'no parts at all' => 'Noise',
        'a prefix that is not Noise' => 'NoiseX_NN_25519_AESGCM_SHA256',
        'an empty pattern part' => 'Noise__25519_AESGCM_SHA256',
        'a pattern name in lower case' => 'Noise_nn_25519_AESGCM_SHA256',
        'nothing at all' => ''
      }.each do |reason, malformed|
        context "with #{reason}" do
          let(:name) { malformed }

          it {
            expect { parsed }
              .to raise_error(Noise::Exceptions::ProtocolNameError, "Malformed protocol name: #{malformed}")
          }
        end
      end
    end

    # A modifier this gem does not implement is written correctly, so it is not the shape of the
    # name that is wrong.
    context 'a modifier this gem does not implement' do
      let(:name) { 'Noise_NNhfs_25519_AESGCM_SHA256' }

      it {
        expect { parsed }
          .to raise_error(Noise::Exceptions::UnsupportedModifierError, 'Unsupported modifier: hfs')
      }
    end

    # Which functions exist is Protocol's question. A name that asks for one this gem lacks is
    # still a well-formed name.
    context 'a function this gem does not implement' do
      let(:name) { 'Noise_NN_9999_NOSUCHCIPHER_NOSUCHHASH' }

      it { expect(parsed.dh_names).to eq ['9999'] }
      it { expect(parsed.cipher_name).to eq 'NOSUCHCIPHER' }
      it { expect(parsed.hash_name).to eq 'NOSUCHHASH' }
    end

    # A stray '+' leaves an empty member behind rather than disappearing, so that such a name
    # cannot pass for the single function written next to it.
    context 'a DH part with an empty member' do
      it { expect(described_class.parse('Noise_NN_25519+_AESGCM_SHA256').dh_names).to eq ['25519', ''] }
      it { expect(described_class.parse('Noise_NN_+25519_AESGCM_SHA256').dh_names).to eq ['', '25519'] }
      it { expect(described_class.parse('Noise_NN__AESGCM_SHA256').dh_names).to eq [] }
    end

    context 'a modifier part with an empty member' do
      let(:name) { 'Noise_NNpsk0++psk1_25519_AESGCM_SHA256' }

      it {
        expect { parsed }
          .to raise_error(Noise::Exceptions::UnsupportedModifierError, 'Unsupported modifier: ')
      }
    end

    context 'the parsed value' do
      let(:name) { 'Noise_NNpsk0_25519+448_AESGCM_SHA256' }

      it 'cannot be changed after parsing' do
        expect(parsed).to be_frozen
        expect { parsed.dh_names << '448' }.to raise_error(FrozenError)
        expect { parsed.modifiers.clear }.to raise_error(FrozenError)
      end
    end
  end
end
