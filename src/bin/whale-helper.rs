fn main() {
    if let Err(error) = whale::cli::helper_main() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
