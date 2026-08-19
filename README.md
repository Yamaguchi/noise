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
    * BLAKE3
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

This gem requires Ruby 3.2 or later, and is tested on 3.2, 3.3, 3.4 and 4.0. Ruby 3.0 and 3.1 are
past end of life and are no longer supported; stay on noise-ruby 0.12.0 or earlier if you need them.

Every function is computed either by the OpenSSL that Ruby is linked against or in pure Ruby, so
no system library has to be installed separately. OpenSSL 1.1.1 or later provides everything this
gem asks of it, and that is what the official Ruby packages and the usual version managers (rbenv,
rvm, asdf) are built with. Two kinds of build fall short: a Ruby linked against LibreSSL has no
BLAKE2b, no ChaCha20-Poly1305 and no X448, and an OpenSSL restricted to the FIPS provider has
neither BLAKE2b nor ChaCha20-Poly1305 nor the secp256k1 curve. On such a build the protocol names
that use a missing function raise an error, and the remaining ones keep working.

Add this line to your application's Gemfile:

```
gem 'noise-ruby'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install noise-ruby

If you use BLAKE3, you must install [Rust and Cargo](https://www.rust-lang.org/tools/install).
And add this line to your Gemfile:

```
gem 'blake3'
```

## Usage

Followings shows handshake protocol with "Noise_NN_25519_ChaChaPoly_BLAKE2b"

### Handshake

#### Supplying keys

Patterns other than `NN` need keys before the handshake starts. `Connection::Initiator.new` and
`Connection::Responder.new` take them in the `keypairs:` hash: `:s` is the local static private key,
`:rs` and `:re` are the remote party's static and ephemeral public keys.

```
initiator = Noise::Connection::Initiator.new("Noise_XX_25519_ChaChaPoly_SHA256", keypairs: { s: static_private_key })
```

`keypairs:` also accepts `:e`, the local ephemeral private key. **It exists only so that
`spec/vectors_spec.rb` can reproduce the official test vectors, which fix both sides' ephemeral keys
to make the output deterministic. Never set it in production.** A connection created with `:e` reuses
that ephemeral keypair instead of generating a fresh one per handshake, which destroys the forward
secrecy every pattern depends on: an attacker who recovers the key can decrypt every session that
used it, past and future. Nothing fails and no warning is printed - the handshake still succeeds and
your own tests still pass - so the loss is invisible. Leave `:e` unset and let the library generate
it.

#### initiator

```
initiator = Noise::Connection::Initiator.new("Noise_NN_25519_ChaChaPoly_BLAKE2b")
initiator.prologue = "test" # => "test"
initiator.start_handshake # => true
cipher = initiator.write_message("") # => "\xB6\xF7gmxi\xAB\xBCY|t\xF0\x9D\x01A\ad\x92\xBBvp\x80ZNU\f=\x83\x81^\xFD\x15"
```

then initiator sends `cipher` to the responder.

#### responder

The responder receives `cipher` from the initiator.
The responder responds messages to the initiator.

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

#### Out-of-order transport messages

Each party counts the transport messages of each direction with a nonce. If the transport layer can
deliver messages out of order or lose them, it has to carry the nonce of each message, and the
receiver sets the nonce before decrypting. Restore the previous value if the message fails to
authenticate, so that the following messages are still decryptable.

```
initiator.encryption_nonce # => 0
responder.decryption_nonce = 2 # decrypt the message numbered 2 next
plain = responder.decrypt(cipher)
```

#### Rekey

Rekeying replaces the key of one direction with `REKEY(k)`, so that a key compromised later cannot
decrypt the messages that came before it. The nonce keeps counting. Both parties must rekey the
matching direction at the same point of the message stream; when that happens is up to the
application protocol.

```
initiator.rekey_encryption
responder.rekey_decryption
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Yamaguchi/noise. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Noise project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/Yamaguchi/noise/blob/master/CODE_OF_CONDUCT.md).
