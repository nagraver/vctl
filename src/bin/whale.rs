fn main() {
    if let Err(error) = whale::cli::public_main() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
