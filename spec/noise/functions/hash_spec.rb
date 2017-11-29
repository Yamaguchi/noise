# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Noise::Functions::Hash do
  describe '.hmac_hash' do
    subject { Noise::Functions::Hash.hmac_hash(key, data, digest).bth }
    context 'SHA256' do
      let(:digest) { 'SHA256' }
      let(:key) { '2b0abd71cb6e7fcc623d554c22b31e90989bddf88690a6e1eeaeafc6004a1a6a'.htb }
      let(:data) { '6e6ceaad64c8cd4607e91ba6009c6384c708d0383e202a11c31dcd678a0f45f402'.htb }
      let(:expected) { '8174979c1cec6952824d45dcdbfe5841deef6d8253396a7e44d3f3ea685cc342' }
      it { is_expected.to eq expected }
    end
    context 'SHA512' do
      let(:digest) { 'SHA512' }
      let(:key) { '43a9c4a9eed5b5046a714e6c8d21636bcbba9b3ebf1e62f3669564851b1477873bdf7e24553188c22614aa6057c98098aa3076110ef5df0000f57f5d958dd92f'.htb }
      let(:data) { 'a87877e1914c742c739b7867c42614ce831476d07b5da17edd895fa7bd0c20549ddd1d3f8dcc808bfb41e72093c68ca99a67c1eca3e9a7422ab93b2ac7800f2302'.htb }
      let(:expected) { '7d2573ddc0e7ac267f9df8d7e16eb55ce94bd58852b706e7e8335c81d7f2891d7357dd642509534639cfd1d75be2863b758c7236837fdad22c5979b306fe5d1e' }
      it { is_expected.to eq expected }
    end
  end

  describe '.hkdf' do
    subject { Noise::Functions::Hash.hkdf(chaining_key, input_key_material, num_outputs, digest).map(&:bth) }
    context 'SHA256 - num_outputs=2' do
      let(:chaining_key) { '4e6f6973655f4e4e5f32353531395f41455347434d5f53484132353600000000'.htb }
      let(:input_key_material) { '934eec08e1e6aad416990e8efcc5aca54520a3ceb2fb2d8bd54ed2bfe4129e2f'.htb }
      let(:num_outputs) { 2 }
      let(:digest) { 'SHA256' }
      let(:expected) do
        [
          '482575c730afad17a501e27b8a119a7e08361d287b5c7e9b9e1d440805a47079',
          '59f4b8088bf038ddc43b506a331c95a96fd754f026c4fe7b1b21444dddbcb502'
        ]
      end
      it { is_expected.to eq expected }
    end
    context 'SHA256 - num_outputs=3' do
      let(:chaining_key) { '094a018a76b104b28b640089a8fa9a57db92c220f291fd062eac94799883da56'.htb }
      let(:input_key_material) { '54686973206973206d7920417573747269616e20706572737065637469766521'.htb }
      let(:num_outputs) { 3 }
      let(:digest) { 'SHA256' }
      let(:expected) do
        [
          '4a9277f61195361b0e4b07f7b5b3f40353420db653e92abdf6045ab925e279dc',
          'f3abc2a2ad61354e63dc3555300fd29087aa8b698b7c55552588d183be898c4f',
          '851ef5e71be15d73a26d08d929762270b66fb98166f780ecaeb7893bfea2c616'
        ]
      end
      it { is_expected.to eq expected }
    end
    context 'SHA512 - num_outputs=2' do
      let(:chaining_key) { '4e6f6973655f4e4e5f32353531395f436861436861506f6c795f5348413531320000000000000000000000000000000000000000000000000000000000000000'.htb }
      let(:input_key_material) { '934eec08e1e6aad416990e8efcc5aca54520a3ceb2fb2d8bd54ed2bfe4129e2f'.htb }
      let(:num_outputs) { 2 }
      let(:digest) { 'SHA512' }
      let(:expected) do
        [
          'bea9be3ec037c9fd921606725c266c727f29c9b076129d0dbc187938a63ac5c5a7c3f091899c9e1b2e382d57ac4576216051cf4f33aba6b12189cd60a7b89afa',
          '03b1a6cc25009fe0da665be832ede23c4527e78edd63b34145001129ae9235cccf98187652f5d6561714f58ba90da1489aa156346e9b8af5929714c83b74eacd'
        ]
      end
      it { is_expected.to eq expected }
    end
    context 'SHA512 - num_outputs=3' do
      let(:chaining_key) { '316bb75d6865b7c22fa67a9f4d74599e892fa37292145b1b7e3d99425fb80cfd4e5fb14e829c7c88749b2c10c2cd845aeda7bc2abb53c8b776cb41bd2d1c2ea0'.htb }
      let(:input_key_material) { '54686973206973206d7920417573747269616e20706572737065637469766521'.htb }
      let(:num_outputs) { 3 }
      let(:digest) { 'SHA512' }
      let(:expected) do
        [
          'c2a5a1534869a81c007b0ab207dbe75ea3ab121c86259efa06c91c96518d67ed132f26217de9acc2c5bf00e1f47a3baca40494ef68a3c6d88224b6b382af55a9',
          '30e3e5c1d79dad644a9873b003ef6d7358e3ac9c75e0d238a6a5cde636d5c37c350a6f6a1bdc0c57edd95cbfdf26fc11f3d64b6133253f347765d8e9314c6c30',
          '6b32535f706a17f18d416c72d7bd9ca34bc0669ce3f0d465f98e2f93349f92d80bbffd0f04359def3157185b86c4fc4f3cf38b40597cbbd1029d999f67a78de8'
        ]
      end
      it { is_expected.to eq expected }
    end
  end
end
