# Noise

A Ruby implementation of the Noise Protocol framework(http://noiseprotocol.org/).

Supported Features:

* DH Functions
    * ED25519
    * ED448
    * Secp256k1
        * Secp256k1 is required for Lightning Network, layer-2 protocol for bitcoin. see [BOLT #8: Encrypted and Authenticated Transport](https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md)
* Cipher Algorithm
    * ChaCha20-Poly1305
    * AES-GCM
* Hash Functions
    * SHA256
    * SHA512
    * BLAKE2s
    * BLAKE2b
* Pattens
    * One-way Patterns(3)
        * N, K, X
    * Fundamental Interactive Patterns(12)
        * NN, KN, NK, KK, NX, KX, XN, IN, XK, IK, XX, IX
    * Defferred Interactive Patterns(23)
        * NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1,K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1
* Fallback
* PSK

## Installation

This gem needs libsodium library.
To install libsodium, see https://github.com/jedisct1/libsodium

Add this line to your application's Gemfile:

```
gem 'noise-ruby'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install noise-ruby

If you use Ed448 as DH function, you must install [libgoldilocks](https://github.com/otrv4/libgoldilocks).

After installing, define an environment variable as follows:

   * on macOS
      
         $ export LIBGOLDILOCKS=/usr/local/lib/libgoldilocks.dylib

   * on Linux(Ubuntu)
   
         $ export LIBGOLDILOCKS=/usr/local/lib/libgoldilocks.so

If you use Secp256k1, you must install [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

    $ git clone https://github.com/bitcoin-core/secp256k1
    $ cd secp256k1
    $ ./autogen.sh
    $ ./configure --enable-module-recovery --enable-experimental --enable-module-ecdh
    $ make
    $ sudo make install

and, add this line to your Gemfile:

```
gem 'secp256k1-ruby'
```

## Usage

Followings shows handshake protocol with "Noise_NN_25519_ChaChaPoly_BLAKE2b"

### Handshake

#### initiator

```
initiator = Noise::Connection::Initiator.new("Noise_NN_25519_ChaChaPoly_BLAKE2b")
initiator.prologue = "test" # => "test"
initiator.start_handshake # => true
cipher = initiator.write_message("") # => "\xB6\xF7gmxi\xAB\xBCY|t\xF0\x9D\x01A\ad\x92\xBBvp\x80ZNU\f=\x83\x81^\xFD\x15"
```

then initiator sends `cipher` to responder.

#### responder

Responder receive `cipher` from initiator.
Responder respond messages to initiator.

```
responder = Noise::Connection::Responder.new("Noise_NN_25519_ChaChaPoly_BLAKE2b")
responder.prologue = "test" # => "test"
responder.start_handshake # => true
plain = responder.read_message(cipher) # => ""
cipher = responder.write_message("") # => "\v\xD9\x97'\xC0\xB1\xC9\xFFD\x8C\x7F\x18L\xB0\xF2\x14\xB0\x11\xC0\x90\xAAZ\xE1\x03\x17z)\xB81/5L\x16\xE3\xD1\xBE<{\xB8\xBB\xD6\xF1\x00\x10]\x99=\xD7"
```


#### initiator

```
plain = initiator.read_message(cipher) # => ""
```

### Transport (after handshake finished)

#### Send transport message 

```
cipher = initiator.encrypt("Hello, World!") # => "\xDA\xC7\xD7as\v\xFA\xCC,\xB3\xC7\xD0/xL\xE8I,\xD9\n\xEExh\x8F\xFA\xD6\x01\x99W"
```

#### Receive transport message

```
plain = responder.decrypt(cipher) # => "Hello, World!"
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/noise. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Noise project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/noise/blob/master/CODE_OF_CONDUCT.md).
