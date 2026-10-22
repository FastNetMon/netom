use clap::Parser;

fn main() {
    let args = bmpdump::cli::Args::parse();
    let code = match bmpdump::cli::run(&args) {
        Ok(code) => code,
        Err(error) => {
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
                || error.downcast_ref::<serde_json::Error>().is_some_and(
                    |e| {
                        e.io_error_kind()
                            == Some(std::io::ErrorKind::BrokenPipe)
                    },
                )
            {
                0
            } else {
                eprintln!(
                    "netom-bmpdump: {}",
                    bmpdump::display::safe(&format!("{error:#}"))
                );
                2
            }
        }
    };
    std::process::exit(code);
}
