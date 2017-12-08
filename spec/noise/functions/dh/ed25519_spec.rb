# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::DH::DH25519 do
  describe '#dh' do
    let(:dh) { Noise::Functions::DH::DH25519.new }
    let(:alice) { dh.generate_keypair }
    let(:bob) { dh.generate_keypair }

    it { expect(dh.dh(alice[0], bob[1])).to eq dh.dh(bob[0], alice[1]) }
  end
end