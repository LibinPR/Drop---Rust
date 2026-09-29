use std::fs;
use std::io::Write;
use std::net::TcpStream;

fn main() {
  let data = fs::read("big.txt").unwrap();

  println!("File has {} bytes" , data.len());

  let mut stream = TcpStream::connect("127.0.0.1:9000").unwrap();

  let file_size = data.len() as u64;

  stream.write_all(&file_size.to_be_bytes()).unwrap();

  stream.write_all(&data).unwrap();
  println!("File Sent!");
}