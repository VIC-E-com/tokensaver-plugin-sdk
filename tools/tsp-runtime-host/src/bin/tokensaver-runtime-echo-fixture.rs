use std::io::{Read, Write};

fn main() {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .expect("fixture stdin");
    if input == b"TS_ARGS" {
        let marker = std::env::var("TOKENSAVER_PLUGIN").unwrap_or_default();
        std::io::stdout()
            .write_all(
                format!(
                    "{marker}\n{}",
                    std::env::args().skip(1).collect::<Vec<_>>().join("\n")
                )
                .as_bytes(),
            )
            .expect("fixture arguments");
    } else {
        std::io::stdout().write_all(&input).expect("fixture stdout");
    }
}
