use std::io::{self, Read, Write};
use std::net::TcpStream;

fn main() {
    println!("Enter the pairing code:");

    let mut code = String::new();

    io::stdin()
        .read_line(&mut code)
        .unwrap();

    let code = code.trim();

    let server_address = "127.0.0.1:9002";

    println!("Connecting to pairing service...");

    let mut stream =
        TcpStream::connect(server_address).unwrap();

    stream
        .write_all(code.as_bytes())
        .unwrap();

    let mut buffer = [0u8; 1024];

    let bytes_read =
        stream.read(&mut buffer).unwrap();

    let response =
        String::from_utf8_lossy(&buffer[..bytes_read]);

    println!("Server response: {}", response);
}