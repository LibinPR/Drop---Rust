use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::net::UdpSocket;
use std::path::Path;

const DISCOVERY_PORT: u16 = 9001;
const TRANSFER_PORT: u16 = 9000;
const DISCOVERY_MESSAGE: &[u8] = b"DROP_DISCOVER";
const DEVICE_KEY_FILE: &str = "device_key.bin";

pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub signing_key: SigningKey,
}

pub fn load_or_create_device_identity() -> DeviceIdentity {
    if Path::new(DEVICE_KEY_FILE).exists() {
        println!("Loading existing device key.");

        let key_bytes =
            fs::read(DEVICE_KEY_FILE)
                .expect("Failed to read device key");

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .expect("Device key must contain exactly 32 bytes");

        let signing_key =
            SigningKey::from_bytes(&key_array);

        let device_id =
            hex_device_id(&signing_key);

        return DeviceIdentity {
            device_id,
            device_name: "Libin-PC".to_string(),
            signing_key,
        };
    }

    println!("Creating new device key.");

    let mut rng = OsRng;

    let signing_key =
        SigningKey::generate(&mut rng);

    fs::write(
        DEVICE_KEY_FILE,
        signing_key.to_bytes(),
    )
    .expect("Failed to save device key");

    let device_id =
        hex_device_id(&signing_key);

    DeviceIdentity {
        device_id,
        device_name: "Libin-PC".to_string(),
        signing_key,
    }
}

fn hex_device_id(signing_key: &SigningKey) -> String {
    let public_key =
        signing_key.verifying_key();

    public_key
        .as_bytes()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

pub fn run_server(identity: DeviceIdentity) {
    let socket =
        UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))
            .expect("Failed to bind discovery socket");

    println!(
        "Discovery server listening on UDP port {}",
        DISCOVERY_PORT
    );

    println!("Device name: {}", identity.device_name);
    println!("Device ID: {}", identity.device_id);

    let mut buffer = [0u8; 1024];

    loop {
        let (bytes_received, sender_address) =
            socket
                .recv_from(&mut buffer)
                .expect("Failed to receive discovery request");

        let message =
            &buffer[..bytes_received];

        if message == DISCOVERY_MESSAGE {
            println!(
                "Discovery request from {}",
                sender_address
            );

            let response = format!(
                "DROP_HERE|{}|{}|{}",
                identity.device_id,
                identity.device_name,
                TRANSFER_PORT
            );

            socket
                .send_to(
                    response.as_bytes(),
                    sender_address,
                )
                .expect("Failed to send discovery response");

            println!(
                "Discovery response sent to {}",
                sender_address
            );
        }
    }
}