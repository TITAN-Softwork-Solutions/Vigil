use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Cli {
    pub config: PathBuf,
    pub verbose: bool,
}

impl Cli {
    pub fn parse() -> Self {
        let mut config = PathBuf::from("config.toml");
        let mut verbose = false;

        let mut args = std::env::args().skip(1).collect::<Vec<_>>();

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--config" | "-c" => {
                    if i + 1 < args.len() {
                        config = PathBuf::from(&args[i + 1]);
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "--verbose" | "-v" => {
                    verbose = true;
                    i += 1;
                }
                _ => {
                    i += 1;
                }
            }
        }

        Self { config, verbose }
    }
}