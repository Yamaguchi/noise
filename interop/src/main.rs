//! A peer built on snow, the Rust implementation of the Noise Protocol Framework, for the Ruby
//! suite in `interop_spec.rb` to run a real handshake against.
//!
//! It speaks over stdin and stdout, framing each Noise message with its length as two big-endian
//! bytes. It reads its whole configuration from the command line, so that the Ruby side decides
//! which protocol runs and which keys each party holds:
//!
//! ```text
//! noise-interop --protocol Noise_XX_25519_ChaChaPoly_SHA256 --role responder \
//!               --prologue 696e7465726f7065726162696c697479 --transport echo \
//!               --handshake-payload 68616e647368616b65 \
//!               [--local-static HEX] [--remote-static HEX] [--psk HEX]
//! ```
//!
//! Every handshake message it writes carries `--handshake-payload`, and every one it reads has to
//! carry the same, so the payload each side encrypts into a handshake message is checked as well
//! as the transcript around it.
//!
//! After the handshake, `--transport` says what it does with each frame that arrives. In every
//! mode the payload `__rekey__` also makes both directions rekey once it has been answered, which
//! is how the transport phase's rekey is exercised.
//!
//! - `echo` decrypts the frame and sends the same payload back encrypted. This is the two-way
//!   case, where both implementations encrypt and both decrypt.
//! - `decrypt` decrypts the frame and sends the payload back in the clear. A one-way pattern
//!   leaves the responder no key to answer with, and proving that it decrypted is the point.
//! - `encrypt` reads a payload in the clear and sends it back encrypted, which is how a one-way
//!   pattern is run in the other direction, with the Ruby side doing the decrypting.

use std::io::{Read, Write};

/// The longest Noise message, which is also the largest a length prefix can announce.
const MAX_MESSAGE: usize = 65535;

/// The payload that asks both sides to rekey once it has been answered.
const REKEY: &[u8] = b"__rekey__";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("a hex argument"))
        .collect()
}

/// Reads one length-prefixed frame, or None once the peer has closed.
fn read_frame<R: Read>(io: &mut R) -> Option<Vec<u8>> {
    let mut prefix = [0u8; 2];
    if io.read_exact(&mut prefix).is_err() {
        return None;
    }
    let mut frame = vec![0u8; u16::from_be_bytes(prefix) as usize];
    io.read_exact(&mut frame).ok()?;
    Some(frame)
}

fn write_frame<W: Write>(io: &mut W, frame: &[u8]) {
    let length = u16::try_from(frame.len()).expect("a frame within the Noise message limit");
    io.write_all(&length.to_be_bytes()).expect("the peer to still be there");
    io.write_all(frame).expect("the peer to still be there");
    io.flush().expect("the peer to still be there");
}

/// What the harness does with each transport frame that arrives.
#[derive(PartialEq)]
enum Mode {
    /// Decrypt it and send the same payload back encrypted.
    Echo,
    /// Decrypt it and send the payload back in the clear.
    Decrypt,
    /// Take the payload in the clear and send it back encrypted.
    Encrypt,
}

struct Options {
    protocol: String,
    role: String,
    local_static: Option<Vec<u8>>,
    remote_static: Option<Vec<u8>>,
    psk: Option<[u8; 32]>,
    prologue: Vec<u8>,
    handshake_payload: Vec<u8>,
    mode: Mode,
}

fn parse_options() -> Options {
    let mut options = Options {
        protocol: String::new(),
        role: String::new(),
        local_static: None,
        remote_static: None,
        psk: None,
        prologue: Vec::new(),
        handshake_payload: Vec::new(),
        mode: Mode::Echo,
    };
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    for pair in arguments.chunks(2) {
        let value = pair.get(1).unwrap_or_else(|| panic!("{} needs a value", pair[0]));
        match pair[0].as_str() {
            "--protocol" => options.protocol = value.clone(),
            "--role" => options.role = value.clone(),
            "--local-static" => options.local_static = Some(hex(value)),
            "--remote-static" => options.remote_static = Some(hex(value)),
            "--psk" => options.psk = Some(hex(value).try_into().expect("a psk of 32 bytes")),
            "--prologue" => options.prologue = hex(value),
            "--handshake-payload" => options.handshake_payload = hex(value),
            "--transport" => {
                options.mode = match value.as_str() {
                    "echo" => Mode::Echo,
                    "decrypt" => Mode::Decrypt,
                    "encrypt" => Mode::Encrypt,
                    unknown => panic!("unknown transport mode {unknown}"),
                }
            }
            unknown => panic!("unknown argument {unknown}"),
        }
    }
    options
}

fn build(options: &Options) -> snow::HandshakeState {
    let params = options.protocol.parse().expect("a Noise protocol name snow understands");
    let mut builder = snow::Builder::new(params).prologue(&options.prologue).expect("a prologue");
    if let Some(ref key) = options.local_static {
        builder = builder.local_private_key(key).expect("a local static key");
    }
    if let Some(ref key) = options.remote_static {
        builder = builder.remote_public_key(key).expect("a remote static key");
    }
    if let Some(ref key) = options.psk {
        // The name says where each psk goes, and this harness is given at most one to place.
        for index in 0..4u8 {
            if options.protocol.contains(&format!("psk{index}")) {
                builder = builder.psk(index, key).expect("a psk");
            }
        }
    }
    match options.role.as_str() {
        "initiator" => builder.build_initiator().expect("an initiator"),
        "responder" => builder.build_responder().expect("a responder"),
        unknown => panic!("unknown role {unknown}"),
    }
}

fn main() {
    let options = parse_options();
    let mut handshake = build(&options);

    let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
    let (mut input, mut output) = (stdin.lock(), stdout.lock());
    let mut buffer = vec![0u8; MAX_MESSAGE];

    while !handshake.is_handshake_finished() {
        if handshake.is_my_turn() {
            let length = handshake
                .write_message(&options.handshake_payload, &mut buffer)
                .expect("to write a handshake message");
            write_frame(&mut output, &buffer[..length]);
        } else {
            let frame = read_frame(&mut input).expect("the peer to finish the handshake");
            let length = handshake.read_message(&frame, &mut buffer).expect("to read a handshake message");
            assert_eq!(
                &buffer[..length],
                &options.handshake_payload[..],
                "the handshake message carried a payload this harness did not expect"
            );
        }
    }

    let mut transport = handshake.into_transport_mode().expect("to reach the transport phase");
    while let Some(frame) = read_frame(&mut input) {
        let payload = if options.mode == Mode::Encrypt {
            frame
        } else {
            let length = transport.read_message(&frame, &mut buffer).expect("to decrypt a transport message");
            buffer[..length].to_vec()
        };

        if options.mode == Mode::Decrypt {
            write_frame(&mut output, &payload);
        } else {
            let length = transport.write_message(&payload, &mut buffer).expect("to encrypt a reply");
            write_frame(&mut output, &buffer[..length]);
        }

        if payload == REKEY {
            transport.rekey_outgoing();
            transport.rekey_incoming();
        }
    }
}
