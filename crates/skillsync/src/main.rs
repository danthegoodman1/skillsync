use clap::Parser;

#[derive(Parser)]
#[command(
    name = "skillsync",
    version,
    about = "Synchronize agent skills between trusted devices"
)]
struct Cli {}

fn main() {
    Cli::parse();
}
