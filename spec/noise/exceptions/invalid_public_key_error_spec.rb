# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Exceptions::InvalidPublicKeyError do
  subject { described_class.new(public_key) }

  let(:public_key) { '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7'.htb }

  it { expect(subject.public_key).to eq public_key }

  it {
    expect(subject.message)
      .to eq 'Invalid public key: 028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7'
  }
end
