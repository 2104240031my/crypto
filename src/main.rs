mod cmd;

#[allow(dead_code)]
mod crypto;

#[allow(dead_code)]
mod test;

fn main() {

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        cmd::println_cmd_usage();
        return;
    }

    match args[1].as_str() {
        "hash" => cmd::cmd_hash::cmd_hash((&args[1..]).to_vec()),
        "help" => cmd::println_cmd_usage(),

        #[cfg(debug_assertions)]
        "test" => test::test(),

        _      => println!("[!Err]: there is no such command."),
    }

}