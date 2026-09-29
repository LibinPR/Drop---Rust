use std::io::Read;
use std::net::TcpListener;
use std::fs;

fn main() {
  let listener = TcpListener::bind("127.0.0.1:9000").unwrap();

  println!("Server is listening on 127.0.0.1:9000");

  for stream in listener.incoming() {
    let mut stream = stream.unwrap();

    //reading file size
    let mut size_buffer = [0u8;8];
    stream.read_exact(&mut size_buffer).unwrap();
    let file_size = u64::from_be_bytes(size_buffer);

    println!("Incoming file: {} bytes", file_size);

    //receive the file
    let mut file_data = Vec::new();
    let mut buffer = [0u8; 1024];

    while file_data.len() < file_size as usize {
      let bytes_read = stream.read(&mut buffer).unwrap();

      if bytes_read == 0{
        break;
      }

      file_data.extend_from_slice(&buffer[..bytes_read]);
     }

    println!("Received {} bytes", file_data.len());
    fs::write("received.txt" , &file_data).unwrap();
    println!("File saves as received.txt");
  }
}
