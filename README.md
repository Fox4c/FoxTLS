# Caesar

A drop-in replacement for the Rust standard library TCP listener with TLSv1.2 enabled.

_Note: This library hasn't been tested._

## Introduction

This library abstracts over a regular TCP listener from the Rust standard library, and provides a drop-in* interface replacement that layers TLSv1.2 with a set of strong cipher suites on top of the connection.

It uses the [OpenSSL library Rust bindings](https://github.com/sfackler/rust-openssl) by Steven Fackler for the underlying TLS functionality. For added security, compile this crate against LibreSSL (instructions provided below).

_* It's only necessary to prepend `Tls` to the regular types (e.g. `TlsTcpListener`), and write error handling code for the new error types._

## Compiling



## Usage

Caesar provides a `CaesarError` enum type, with a variant for I/O errors and another one for SSL errors. You can find the specifics in the [library docs]().

```rust
extern crate caesar;

use caesar::{TlsTcpListener, TlsTcpStream};
use std::thread;

let key_path = "path_to_certs/key.pem";
let cert_path = "path_to_certs/cert.pem";

let listener = TlsTcpListener::bind("127.0.0.1:8080", key_path, cert_path).unwrap()

fn handle_client(stream: TlsTcpStream) {
    // ...
}

// accept connections and process them, spawning a new thread for each one
for stream in listener.incoming() {
    match stream {
        Ok(stream) => {
            thread::spawn(move || {
                // connection succeeded
                handle_client(stream)
            });
        }
        Err(e) => { /* connection failed */ }
    }
}

// close the socket server
drop(listener);
```

## Notes

This crate was written to satisfy my needs while writing [Postage](https://github.com/Postage/postage). As such, only a minimal set of functions was ported over from the `TcpListener` interface. I might continue to expand this set of functions as the need arises; if you need the functionality earlier, and I haven't implemented it yet, you are welcome to contribute.

## To Do

- [ ] Write tests
- [ ] Write proper documentation
- [ ] Code review

## License

This code is licensed under the MIT License. See `LICENSE`.
