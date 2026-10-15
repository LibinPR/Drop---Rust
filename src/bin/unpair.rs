use std::fs;
use std::path::Path;

fn main() {
    const TRUSTED_PC_FILE: &str = "trusted_pc_id.txt";

    if !Path::new(TRUSTED_PC_FILE).exists() {
        println!("No trusted PC is currently saved. Nothing to unpair.");
        return;
    }

    println!("This will remove the saved trusted PC identity.");
    println!("You will need to pair again before sending files.");

    print!("Continue? Type YES to confirm: ");

    use std::io::{self, Write};
    io::stdout().flush().expect("Failed to flush output");

    let mut confirmation = String::new();

    if io::stdin().read_line(&mut confirmation).is_err() {
        eprintln!("Failed to read confirmation.");
        std::process::exit(1);
    }

    if confirmation.trim() != "YES" {
        println!("Unpair cancelled.");
        return;
    }

    match fs::remove_file(TRUSTED_PC_FILE) {
        Ok(()) => println!("PC unpaired successfully."),
        Err(error) => {
            eprintln!("Failed to unpair PC: {error}");
            std::process::exit(1);
        }
    }
}
