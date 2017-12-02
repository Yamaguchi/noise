# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Protocol do
  describe '#required_keypairs' do
    subject { Noise::Pattern.create(name).required_keypairs(initiator) }

    describe 'NN(initiator)' do
      let(:initiator) { true }
      let(:name) { 'NN' }
      it { is_expected.to eq [] }
    end
    describe 'NN(responder)' do
      let(:initiator) { false }
      let(:name) { 'NN' }
      it { is_expected.to eq [] }
    end
    describe 'KN(initiator)' do
      let(:initiator) { true }
      let(:name) { 'KN' }
      it { is_expected.to eq [:s] }
    end
    describe 'KN(responder)' do
      let(:initiator) { false }
      let(:name) { 'KN' }
      it { is_expected.to eq [:rs] }
    end
    describe 'NK(initiator)' do
      let(:initiator) { true }
      let(:name) { 'NK' }
      it { is_expected.to eq [:rs] }
    end
    describe 'NK(responder)' do
      let(:initiator) { false }
      let(:name) { 'NK' }
      it { is_expected.to eq [:s] }
    end
    describe 'KK(initiator)' do
      let(:initiator) { true }
      let(:name) { 'KK' }
      it { is_expected.to eq [:s, :rs] }
    end
    describe 'KK(responder)' do
      let(:initiator) { false }
      let(:name) { 'KK' }
      it { is_expected.to eq [:rs, :s] }
    end
    describe 'NX(initiator)' do
      let(:initiator) { true }
      let(:name) { 'NX' }
      it { is_expected.to eq [] }
    end
    describe 'NX(responder)' do
      let(:initiator) { false }
      let(:name) { 'NX' }
      it { is_expected.to eq [:s] }
    end
    describe 'KX(initiator)' do
      let(:initiator) { true }
      let(:name) { 'KX' }
      it { is_expected.to eq [:s] }
    end
    describe 'KX(responder)' do
      let(:initiator) { false }
      let(:name) { 'KX' }
      it { is_expected.to eq [:rs, :s] }
    end
    describe 'XN(initiator)' do
      let(:initiator) { true }
      let(:name) { 'XN' }
      it { is_expected.to eq [:s] }
    end
    describe 'XN(responder)' do
      let(:initiator) { false }
      let(:name) { 'XN' }
      it { is_expected.to eq [] }
    end
    describe 'IN(initiator)' do
      let(:initiator) { true }
      let(:name) { 'IN' }
      it { is_expected.to eq [:s] }
    end
    describe 'IN(responder)' do
      let(:initiator) { false }
      let(:name) { 'IN' }
      it { is_expected.to eq [] }
    end
    describe 'XK(initiator)' do
      let(:initiator) { true }
      let(:name) { 'XK' }
      it { is_expected.to eq [:s, :rs] }
    end
    describe 'XK(responder)' do
      let(:initiator) { false }
      let(:name) { 'XK' }
      it { is_expected.to eq [:s] }
    end
    describe 'IK(initiator)' do
      let(:initiator) { true }
      let(:name) { 'IK' }
      it { is_expected.to eq [:s, :rs] }
    end
    describe 'IK(responder)' do
      let(:initiator) { false }
      let(:name) { 'IK' }
      it { is_expected.to eq [:s] }
    end
    describe 'XX(initiator)' do
      let(:initiator) { true }
      let(:name) { 'XX' }
      it { is_expected.to eq [:s] }
    end
    describe 'XX(responder)' do
      let(:initiator) { false }
      let(:name) { 'XX' }
      it { is_expected.to eq [:s] }
    end
    describe 'IX(initiator)' do
      let(:initiator) { true }
      let(:name) { 'IX' }
      it { is_expected.to eq [:s] }
    end
    describe 'IX(responder)' do
      let(:initiator) { false }
      let(:name) { 'IX' }
      it { is_expected.to eq [:s] }
    end
    describe 'N(initiator)' do
      let(:initiator) { true }
      let(:name) { 'N' }
      it { is_expected.to eq [:rs] }
    end
    describe 'N(responder)' do
      let(:initiator) { false }
      let(:name) { 'N' }
      it { is_expected.to eq [:s] }
    end
    describe 'K(initiator)' do
      let(:initiator) { true }
      let(:name) { 'K' }
      it { is_expected.to eq [:s, :rs] }
    end
    describe 'K(responder)' do
      let(:initiator) { false }
      let(:name) { 'K' }
      it { is_expected.to eq [:rs, :s] }
    end
    describe 'X(initiator)' do
      let(:initiator) { true }
      let(:name) { 'X' }
      it { is_expected.to eq [:s, :rs] }
    end
    describe 'X(responder)' do
      let(:initiator) { false }
      let(:name) { 'X' }
      it { is_expected.to eq [:s] }
    end
  end
end
