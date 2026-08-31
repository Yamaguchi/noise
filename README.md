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

Every function except BLAKE3, which is optional and covered below, is computed either by the
OpenSSL that Ruby is linked against or in pure Ruby, so no system library has to be installed
separately. OpenSSL 1.1.1 or later provides everything this gem asks of it, and that is what the
official Ruby packages and the usual version managers (rbenv, rvm, asdf) are built with. Two kinds
of build fall short: a Ruby linked against LibreSSL has no BLAKE2b, no ChaCha20-Poly1305 and no
X448, and an OpenSSL restricted to the FIPS provider has neither BLAKE2b nor ChaCha20-Poly1305 nor
the secp256k1 curve. On such a build the protocol names that use a missing function raise an error,
and the remaining ones keep working.

Add this line to your application's Gemfile:

```
gem 'noise-ruby'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install noise-ruby

If you use BLAKE3, add this line to your Gemfile:

```
gem 'blake3-rb'
```

`blake3-rb` ships precompiled binaries for common Linux, macOS and Windows platforms (x86_64 and
aarch64), so no Rust or C toolchain is needed to install it there. On any other platform bundler
falls back to the source gem, which does need a C compiler.

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
initiator.start_handshake
cipher = initiator.write_message("") # => "\xB6\xF7gmxi\xAB\xBCY|t\xF0\x9D\x01A\ad\x92\xBBvp\x80ZNU\f=\x83\x81^\xFD\x15"
```

then initiator sends `cipher` to the responder.

#### responder

The responder receives `cipher` from the initiator.
The responder responds messages to the initiator.

```
responder = Noise::Connection::Responder.new("Noise_NN_25519_ChaChaPoly_BLAKE2b")
responder.prologue = "test" # => "test"
responder.start_handshake
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

### Thread safety

One connection belongs to one thread. A `Noise::Connection` holds its handshake state and its
transport nonces in plain instance variables and never locks, so two threads that share one
connection can encrypt two different plaintexts under the same nonce. That is not a small loss for
either cipher this gem implements: reusing a nonce breaks the confidentiality of both messages and
lets an attacker forge further ones.

If an application has to reach one connection from more than one thread, it is responsible for
serialising every call to it.

This is deliberate rather than an omission. A lock inside the connection would make each call
atomic without making concurrent use correct, because the transport nonce numbers the messages of
a direction: two threads that both encrypt still produce a stream in an order the receiver cannot
reconstruct. Only the application knows which message comes first, and deciding that order is
itself the serialisation the lock cannot supply.

Receiving is no easier. Decrypting a message that arrived out of order is a `decryption_nonce=`
call followed by a `decrypt` call, and no lock taken one call at a time holds those two together.

### Half-duplex mode

Section 11.5 of the Noise specification describes protocols in which the two parties strictly take
turns. Such a protocol may keep a single `CipherState` for both directions instead of one per
direction, which halves what each party has to store after the handshake. Pass `half_duplex: true`
to both parties to run that way.

```
initiator = Noise::Connection::Initiator.new("Noise_NN_25519_ChaChaPoly_SHA256", half_duplex: true)
responder = Noise::Connection::Responder.new("Noise_NN_25519_ChaChaPoly_SHA256", half_duplex: true)
```

Because there is one `CipherState`, the methods that name a direction all reach it:
`encryption_nonce` and `decryption_nonce` report the same count, setting either sets both, and
`rekey_encryption` and `rekey_decryption` replace the same key.

**The two parties must strictly alternate their transport messages.** They share one nonce, so a
message in either direction advances the count both of them keep. If both parties encrypt before
either decrypts, the two messages go out under the same nonce, which breaks the confidentiality of
both and lets an attacker forge further ones. Nothing in this gem can detect that: it is the
application protocol that has to guarantee the turn taking.

Use it only when the protocol you are implementing calls for it. It is off by default, and a
one-way pattern refuses it, because such a pattern has no messages to alternate.

### Lightning Network (BOLT #8)

BOLT #8 is the transport the Lightning Network runs on: a `Noise_XK_secp256k1_ChaChaPoly_SHA256`
handshake, then a byte stream in which every message is preceded by its own encrypted length.
`Noise::Lightning::Transport` owns that framing, so an application only has to run the handshake
and hand over the finished connection.

```
name = Noise::Lightning::Transport::PROTOCOL_NAME

initiator = Noise::Connection::Initiator.new(name, keypairs: { s: local_static, rs: node_id })
initiator.prologue = Noise::Lightning::Transport::PROLOGUE
initiator.start_handshake
# ... exchange the three handshake messages over the socket ...

transport = Noise::Lightning::Transport.new(initiator)
socket.write(transport.write("a lightning message"))
message = transport.read(socket)
```

`#write` returns the bytes to send: the payload length as a two-byte big-endian integer encrypted
on its own, then the encrypted payload. `#read` takes anything that answers `read(length)`, reads
the length, and then reads and decrypts that many bytes. It raises `TruncatedMessageError` if the
stream ends part way through a message, and `DecryptError` if either half fails to authenticate —
BOLT #8 requires the connection to be closed when that happens.

Each direction replaces its key with `HKDF(ck, k)` once its nonce reaches 1000, which is every 500
messages because each message is encrypted twice. This is not the `rekey_encryption` of the Noise
specification: it draws on the chaining key the handshake ended with, so a key stolen now says
nothing about the keys that direction used before it. The transport does it on its own; nothing
has to be called.

The transport takes over the connection's transport phase: it holds the very `CipherState`s the
connection does. Once a connection is wrapped, stop calling its `encrypt`, `decrypt`, nonce
accessors and rekey methods, because each of them moves the same key and nonce and the peer has no
way to learn that they did. A half-duplex connection is refused outright, since BOLT #8 gives each
direction a key of its own.

Nothing else in the gem loads this. An application that does not speak Lightning never names
`Noise::Lightning`, and never pays for it.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Yamaguchi/noise. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Noise project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/Yamaguchi/noise/blob/master/CODE_OF_CONDUCT.md).
