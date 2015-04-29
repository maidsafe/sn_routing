extern crate docopt;
extern crate rustc_serialize;

use docopt::Docopt;
use std::thread::spawn;
use std::io;

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
    GET, PUT, NONE
}

#[derive(RustcDecodable, Debug)]
enum Action {
    SEND, RECIEVE
}

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_type : Option<OperationType>,
    arg_size : Option<u8>,
    flag_size : bool,
    flag_help : bool
}

fn get_op_type(str: &str) -> OperationType {
    match str {
        "GET" => OperationType::GET,
        "PUT" => OperationType::PUT,
        _ => OperationType::NONE,
    }
}

fn handle_send(v : Vec<&str>) {
    println!("Sending {}", v[1]);
    if v.len() == 3 {
        println!("{:?}", get_op_type(v[2].trim()));
    }
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
    let mut command = String::new();
    loop {
        command.clear();
        println!("Input command (stop, send <msg> <type>)");
        let _ = io::stdin().read_line(&mut command);
        let v: Vec<&str> = command.split(' ').collect();
        match v[0].trim() {
            "stop" => break,
            "send" => {
                handle_send(v)
            },
            _ => println!("Invalid Option")
        }
    }
}
