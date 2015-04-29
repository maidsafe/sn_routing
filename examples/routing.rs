extern crate docopt;
extern crate rustc_serialize;

use docopt::Docopt;

static USAGE: &'static str = "
Usage: routing -h
       routing <type> -s <size>

Options:
    -h, --help       Display the help message.
    -s, --size       Size numeric type
";

// cargo run --example routing -- GET -s 60

#[derive(RustcDecodable, Debug)]
enum OperationType {
    GET, PUT
}

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_type : Option<OperationType>,
    arg_size : Option<u8>,
    flag_size : bool,
    flag_help : bool
}

fn main() {
    let args : Args = Docopt::new(USAGE)
                     .and_then(|d| d.decode())
                     .unwrap_or_else(|e| e.exit());
    if args.flag_help {
        println!("{:?}", args);
        return;
    }
    println!("Type :: {:?}", args.arg_type.unwrap());    
    if args.arg_size.is_some() {
        println!("Size :: {:?}", args.arg_size.unwrap());
    }
}
