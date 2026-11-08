use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::{
    fs,
    io::{Cursor, Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
};
fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
    for mode in ["http", "websocket"] {
        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        if mode == "http" {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        for i in 0..3 {
            let mut client =
                ClientConnection::new(Arc::new(config.clone()), "chatgpt.com".try_into().unwrap())
                    .unwrap();
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            fs::write(format!("{mode}-{i}.bin"), &bytes).unwrap();
            if i == 0 {
                let body = &bytes[9..];
                let sid_len = body[34] as usize;
                let sid = &body[35..35 + sid_len];
                let mut hrr = vec![3, 3];
                hrr.extend_from_slice(&[
                    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
                    0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e,
                    0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
                ]);
                hrr.push(sid_len as u8);
                hrr.extend_from_slice(sid);
                hrr.extend_from_slice(&[
                    0x13, 0x02, 0, 0, 12, 0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0x11, 0xec,
                ]);
                let mut hs = vec![2, 0, 0, hrr.len() as u8];
                hs.extend(hrr);
                let mut record = vec![22, 3, 3, (hs.len() >> 8) as u8, hs.len() as u8];
                record.extend(hs);
                client.read_tls(&mut Cursor::new(record)).unwrap();
                client.process_new_packets().unwrap();
                let mut second = Vec::new();
                client.write_tls(&mut second).unwrap();
                fs::write(format!("{mode}-hrr.bin"), second).unwrap();
            }
        }
    }
    if let Ok(addr) = std::env::var("TLS_REF_ADDR") {
        let mut roots = RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                fs::read("cert.der").unwrap(),
            ))
            .unwrap();
        for mode in ["http", "websocket"] {
            let mut config = ClientConfig::builder()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            if mode == "http" {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            let config = Arc::new(config);
            for attempt in 0..2 {
                let writes = Arc::new(Mutex::new(Vec::new()));
                let wire = Wire {
                    tcp: TcpStream::connect(&addr).unwrap(),
                    writes: writes.clone(),
                };
                let connection =
                    ClientConnection::new(config.clone(), "chatgpt.com".try_into().unwrap())
                        .unwrap();
                let mut stream = rustls::StreamOwned::new(connection, wire);
                stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let mut response = Vec::new();
                let _ = stream.read_to_end(&mut response);
                let bytes = writes.lock().unwrap();
                let length = 5 + u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
                fs::write(format!("{mode}-resumption-{attempt}.bin"), &bytes[..length]).unwrap();
            }
        }
    }
}

struct Wire {
    tcp: TcpStream,
    writes: Arc<Mutex<Vec<u8>>>,
}
impl Read for Wire {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.tcp.read(b)
    }
}
impl Write for Wire {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.tcp.write(b)?;
        self.writes.lock().unwrap().extend_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}
