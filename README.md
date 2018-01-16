# Noise

A Ruby implementation of the Noise Protocol framework(http://noiseprotocol.org/).

## Secp256k1

Secp256k1 cipher function is supported.
This is required for Lightning Network, layer-2 protocol for bitcoin.

see https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md

## Future Works

The followings are not supported yet.

- DH Functions
  - Curve448
- Hash Functions
  - Blake2s

## Installation

This library requires [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

    $ git clone https://github.com/bitcoin-core/secp256k1
    $ cd secp256k1
    $ ./autogen.sh
    $ ./configure --enable-experimental --enable-module-ecdh --enable-module-recovery --enable-benchmark=false
    $ make
    $ sudo make install

In addition, libsodium is required.

    $ brew install libsodium


Add this line to your application's Gemfile:

```
gem 'noise-ruby'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install noise-ruby

## Usage

TODO: Write usage instructions here

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/noise. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Noise project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/noise/blob/master/CODE_OF_CONDUCT.md).
