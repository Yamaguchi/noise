# Interoperability with snow

The vectors in `spec/vectors/` are replayed transcripts. They catch a wrong primitive or a wrong
message, but both sides of every one of those tests are this gem reading a recording, so a
misreading of the specification that the recording happens to share goes unnoticed.

This directory runs the other kind of test: a real handshake, and then a real transport exchange,
between this gem and [snow](https://github.com/mcginty/snow), the Rust implementation of the Noise
Protocol Framework.

## Running it

It is not part of `bundle exec rspec`, so that a contributor without a Rust toolchain can still
run the suite.

```sh
cd interop && cargo build --release && cd ..
bundle exec rake interop
```

## What it covers

Eighteen patterns against five cipher and hash suites, each run in both directions — this gem as
the initiator and as the responder, except for the one-way patterns, where the responder has
nothing to send and instead decrypts what the other implementation encrypted:

- the one-way family, `N` `K` `X`
- the twelve interactive fundamentals, `NN` through `IX`
- `NNpsk0` and `XXpsk3`, which put a pre-shared key at each end of a handshake
- `K1X1`, a deferred pattern
- `ChaChaPoly` and `AESGCM` against `SHA256`, `SHA512`, `BLAKE2s` and `BLAKE2b`

Every handshake message carries a payload, which both sides check, so the encrypted handshake
payload is covered as well as the transcript around it. Each run then exchanges an ordinary
payload, a zero-length one, one over a kilobyte, the longest a Noise message can carry, and —
after rekeying both directions — one more.

## What it does not cover

snow implements none of `448`, `secp256k1`, `BLAKE3` or the `fallback` modifier, so `25519` is the
only DH function the two have in common and those four are still covered only by the vectors.

Covering them needs a second reference implementation. noise-c has `448`, and would answer for
that one.

## How it works

`src/main.rs` builds a small binary that speaks over stdin and stdout, framing each Noise message
with its length as two big-endian bytes. It takes the protocol name, its role and its keys from
the command line, so the Ruby side decides everything about both parties and knows every key in
play.

After the handshake, `--transport` says what it does with each frame that arrives.

- `echo` decrypts it and sends the same payload back encrypted, which is the two-way case: both
  implementations encrypt and both decrypt.
- `decrypt` decrypts it and sends the payload back in the clear, because a one-way pattern leaves
  the harness no key to answer with. Proving that it decrypted is the point of the exchange.
- `encrypt` takes a payload in the clear and sends it back encrypted, which is how a one-way
  pattern is run in the other direction, with this gem doing the decrypting.

In every mode the payload `__rekey__` also makes both directions rekey once it has been answered.

`interop_spec.rb` drives it, `peer.rb` owns the process and the framing, and `matrix.rb` lists what
runs.
