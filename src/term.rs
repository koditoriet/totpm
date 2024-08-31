use std::{fmt::Display, io::{IsTerminal, Write}};


pub fn pick_one<'a, T: Display, I: Iterator<Item = &'a T>>(msg: &str, items: I) -> Option<&'a T> {
    let alts: Vec<&'a T> = items.collect();
    match alts.len() {
        0 => None,
        1 => Some(alts[0]),
        num_alts => {
            if !std::io::stdout().is_terminal() {
                return None
            }
            println!("{}", msg);
            println!("0:\t[cancel]");
            for (i, item) in alts.iter().enumerate() {
                println!("{}:\t{}", i + 1, item);
            }
            let mut response = String::new();
            loop {
                print!("> ");
                std::io::stdout().flush().unwrap();
                std::io::stdin().read_line(&mut response).unwrap();
                let ix = response.trim().parse::<usize>().ok()?;
                if ix == 0 {
                    log::info!("selection cancelled");
                    return None
                } else if ix <= num_alts {
                    return Some(alts[ix - 1])
                } else {
                    println!("invalid selection")
                }
            }        
        }
    }
}
