use std::{fmt::Display, io::{BufRead, IsTerminal, Stdout, Write}};


/// Since we can't implement IsTerminal, we need a custom trait
/// to make this testable.
pub trait IsATTY {
    fn isatty(&self) -> bool;
}


impl IsATTY for Stdout {
    fn isatty(&self) -> bool {
        self.is_terminal()
    }
}


pub fn pick_one<'a, T: Display, I: Iterator<Item = &'a T>, In: BufRead, Out: Write + IsATTY>(
    inp: &mut In,
    out: &mut Out,
    msg: &str,
    items: I
) -> Option<&'a T> {
    let alts: Vec<&'a T> = items.collect();
    match alts.len() {
        0 => None,
        1 => Some(alts[0]),
        num_alts => {
            if !out.isatty() {
                return None
            }
            out.write_fmt(format_args!("{}\n", msg)).unwrap();
            out.write_fmt(format_args!("0:\t[cancel]\n")).unwrap();
            for (i, item) in alts.iter().enumerate() {
                out.write_fmt(format_args!("{}:\t{}\n", i + 1, item)).unwrap();
            }
            let mut response = String::new();
            loop {
                out.write_fmt(format_args!("> ")).unwrap();
                out.flush().unwrap();
                inp.read_line(&mut response).unwrap();
                let ix = response.trim().parse::<usize>().ok()?;
                if ix == 0 {
                    log::info!("selection cancelled");
                    return None
                } else if ix <= num_alts {
                    return Some(alts[ix - 1])
                } else {
                    out.write_fmt(format_args!("invalid selection\n")).unwrap()
                }
            }        
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use testutil::{MockStdout, MockTerminal};

    use super::*;

    impl <'a> IsATTY for MockStdout<'a> {
        fn isatty(&self) -> bool {
            true
        }
    }

    impl IsATTY for Vec<u8> {
        fn isatty(&self) -> bool {
            false
        }
    }

    #[test]
    fn pick_one_returns_none_on_non_terminal_input() {
        assert_eq!(
            pick_one(&mut VecDeque::new(), &mut Vec::new(), "hello", vec![1,2,3].iter()),
            None,
        )
    }

    #[test]
    fn pick_one_returns_none_on_empty_input() {
        let mut term = MockTerminal::new();
        let (mut inp, mut out) = term.stdin_stdout();
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", vec![].iter()),
            None as Option<&u32>,
        )
    }

    #[test]
    fn pick_one_returns_none_on_cancel() {
        let mut term = MockTerminal::new().write_stdin("0");
        let (mut inp, mut out) = term.stdin_stdout();
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", vec![1, 2, 3].iter()),
            None as Option<&u32>,
        )
    }

    #[test]
    fn pick_one_returns_only_alternative_without_prompt() {
        let mut term = MockTerminal::new();
        let (mut inp, mut out) = term.stdin_stdout();
        let mut non_terminal_stdout = Vec::new();
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", vec!["x"].iter()),
            Some(&"x"),
        );
        assert_eq!(
            pick_one(&mut inp, &mut non_terminal_stdout, "hello", vec!["x"].iter()),
            Some(&"x"),
        );
    }

    #[test]
    fn pick_one_warns_and_returns_nothing_on_invalid_selection() {
        let mut term = MockTerminal::new()
            .expect_stdout("hello\n")
            .expect_stdout("0:\t[cancel]\n")
            .expect_stdout("1:\tfoo\n")
            .expect_stdout("2:\tbar\n")
            .expect_stdout("> ")
            .write_stdin("3")
            .expect_stdout("invalid selection\n")
            .expect_stdout("> ")
            .write_stdin("1");
        let (mut inp, mut out) = term.stdin_stdout();
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", vec!["foo", "bar"].iter()),
            None as Option<&&str>,
        );
    }

    #[test]
    fn pick_one_outputs_prompt() {
        let mut term = MockTerminal::new()
            .expect_stdout("hello\n")
            .expect_stdout("0:\t[cancel]\n")
            .expect_stdout("1:\tfoo\n")
            .expect_stdout("2:\tbar\n")
            .expect_stdout("3:\tbaz\n")
            .expect_stdout("> ")
            .write_stdin("0");
        let (mut inp, mut out) = term.stdin_stdout();
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", vec!["foo", "bar", "baz"].iter()),
            None as Option<&&str>,
        );
    }

    #[test]
    fn pick_one_returns_chosen_input() {
        let items = vec![1, 2, 3, 4, 5];
        let mut term = MockTerminal::new()
            .wait_stdout()
            .write_stdin("1") // First item
            .wait_stdout()
            .write_stdin("5") // Last item
            .wait_stdout()
            .write_stdin("2"); // Some other item
        let (mut inp, mut out) = term.stdin_stdout();
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", items.iter()),
            Some(&1u32),
        );
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", items.iter()),
            Some(&5u32),
        );
        assert_eq!(
            pick_one(&mut inp, &mut out, "hello", items.iter()),
            Some(&2u32),
        );
    }
}
