use std::net::UdpSocket;

const DISCOVERY_PORT: u16 = 9001;

const DISCOVERY_MESSAGE: &[u8] = b"DROP_DISCOVER";
const RESPONSE_MESSAGE: &[u8] = b"DROP_HERE|Libin-PC|9000";

pub fn run_server() {
    let socket = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).unwrap();

    println!(
        "Discovery server listening on UDP port {}",
        DISCOVERY_PORT
    );

    let mut buffer = [0u8; 1024];

    loop {
        let (bytes_received, sender_address) =
            socket.recv_from(&mut buffer).unwrap();

        let message = &buffer[..bytes_received];

        if message == DISCOVERY_MESSAGE {
            println!("Discovery request from {}", sender_address);

            socket
                .send_to(RESPONSE_MESSAGE, sender_address)
                .unwrap();

            println!(
                "Discovery response sent to {}",
                sender_address
            );
        }
    }
}