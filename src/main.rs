use clap::Parser;

mod perf;
mod args;

fn main() {
	let args = args::Args::parse();
	let mut perf = perf::Perf::new(args.pid);
	let _ = perf.exec(&args);
}
