use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, TcpListener, TcpStream};

use openssl::ssl::{self, SslMethod, Ssl, SslStream};
use openssl::x509::X509FileType;

use super::types::{CaesarError, Result};

pub struct TlsTcpListener {
    listener: TcpListener,
    ssl: Ssl,
}

pub struct TlsTcpStream {
    stream: SslStream<TcpStream>,
}

pub struct Incoming<'a> {
    listener: &'a TlsTcpListener,
}

impl TlsTcpListener {
    pub fn bind<A: ToSocketAddrs>(addr: A, key: &str, cert: &str) -> Result<TlsTcpListener> {
        // set up context
        let mut ctx = try!(ssl::SslContext::new(SslMethod::Tlsv1_2)
                               .map_err(|e| CaesarError::Ssl(e)));
        try!(ctx.set_cipher_list("ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:\
                                  DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:\
                                  !MD5:!DSS")
                .map_err(|e| CaesarError::Ssl(e)));
        try!(ctx.set_private_key_file(key, X509FileType::PEM).map_err(|e| CaesarError::Ssl(e)));
        try!(ctx.set_certificate_file(cert, X509FileType::PEM).map_err(|e| CaesarError::Ssl(e)));
        try!(ctx.check_private_key().map_err(|e| CaesarError::Ssl(e)));

        // create ssl instance
        let ssl = try!(Ssl::new(&ctx).map_err(|e| CaesarError::Ssl(e)));

        // create listener
        let listener = try!(TcpListener::bind(addr).map_err(|e| CaesarError::Io(e)));
        Ok(TlsTcpListener {
            listener: listener,
            ssl: ssl,
        })
    }

    pub fn accept(&self) -> Result<(TlsTcpStream, SocketAddr)> {
        let (stream, addr) = try!(self.listener.accept().map_err(|e| CaesarError::Io(e)));
        let tls_stream = try!(SslStream::accept(self.ssl.clone(), stream)
                                  .map_err(|e| CaesarError::Ssl(e)));
        Ok((TlsTcpStream { stream: tls_stream }, addr))
    }

    pub fn incoming(&self) -> Incoming {
        Incoming { listener: self }
    }
}

impl<'a> Iterator for Incoming<'a> {
    type Item = Result<TlsTcpStream>;
    fn next(&mut self) -> Option<Result<TlsTcpStream>> {
        Some(self.listener.accept().map(|p| p.0))
    }
}

impl TlsTcpStream {
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.stream.get_ref().peer_addr().map_err(|e| CaesarError::Io(e))
    }
}

impl Read for TlsTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TlsTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
