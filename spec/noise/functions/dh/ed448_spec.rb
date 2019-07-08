# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::DH::ED448 do
  # https://tools.ietf.org/html/rfc7748#section-6.2
  describe '#dh' do
    let(:private_key) do
      '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d' \
      'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'.htb
    end
    let(:public_key) do
      '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430' \
      '27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609'.htb
    end
    let(:shared_key) do
      '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b' \
      'b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d'
    end
    let(:ed448) { Noise::Functions::DH::ED448.new }
    subject { ed448.dh(private_key, public_key).bth }
    it { is_expected.to eq shared_key }
  end

  describe '#generate_keypair' do
    let(:dh) { Noise::Functions::DH::ED448.new }
    let(:alice) { dh.generate_keypair }
    let(:bob) { dh.generate_keypair }
    it { expect(dh.dh(alice.private_key, bob.public_key)).to eq dh.dh(bob.private_key, alice.public_key) }
  end
end
