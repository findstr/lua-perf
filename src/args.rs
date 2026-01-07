use clap::Parser;

#[derive(Parser)]
#[command(name = "lua-perf")]
#[command(author = "findstr <findstrx@gmail.com>")]
#[command(version = "0.2")]
#[command(about = "A perf tool for C and Lua hybrid code")]
pub struct Args {
        #[arg(short, long, help = "PID of the process to profile")]
        pub pid: libc::pid_t,
        #[clap(short, long, default_value_t = 100, help="Profile sample frequency(HZ)")]
        pub freq: u64,
}