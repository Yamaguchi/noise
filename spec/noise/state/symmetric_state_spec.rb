# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::State::SymmetricState do
  let(:state) do
    Noise::State::SymmetricState.new.tap do |state|
      state.initialize_symmetric(protocol_name: 'Noise_NN_25519_ChaChaPoly_SHA256')
    end
  end
  describe '#initialize_symmetric' do
    subject { state }
    let(:expected) { '4e6f6973655f4e4e5f32353531395f436861436861506f6c795f534841323536'.htb }
    it { expect(subject.h).to eq expected }
  end

  describe '#mix_hash' do
    let(:data) { '4a6f686e2047616c74'.htb }
    subject { state.tap { |s| s.mix_hash(data) } }
    let(:expected) { 'ed35952131cddb48db399ee546582ca13649bf2bb3e93596d334c7a55897ec64' }
    it { expect(subject.h.bth).to eq expected }
  end

  describe '#mix_key' do
    let(:input_key_material) { '934eec08e1e6aad416990e8efcc5aca54520a3ceb2fb2d8bd54ed2bfe4129e2f'.htb }
    subject { state.tap { |s| s.mix_key(input_key_material) } }
    let(:expected) { '8e95b1fa950086b4b1aa02f860122faa7666c3a7d67be1b6fdc418b20b3a0b52' }
    it { expect(subject.ck.bth).to eq expected }
  end
end
