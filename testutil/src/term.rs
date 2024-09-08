use std::{collections::VecDeque, io::{BufRead, Read, Write}, sync::{Arc, Mutex}};

#[derive(Debug)]
enum TermAction {
    Write(VecDeque<u8>),
    Read,
    Expect(String),
}

pub struct MockTerminal {
    actions: VecDeque<TermAction>,
    stdin_buffer: VecDeque<u8>,
    stdout_buffer: Vec<u8>,
    output: Vec<String>,
}

pub struct MockStdin<'a> {
    term: Arc<Mutex<&'a mut MockTerminal>>,
    temp_buf: Vec<u8>,
}

pub struct MockStdout<'a> {
    term: Arc<Mutex<&'a mut MockTerminal>>,
}

impl Default for MockTerminal {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTerminal {
    pub fn new() -> Self {
        MockTerminal {
            actions: VecDeque::new(),
            stdin_buffer: VecDeque::new(),
            stdout_buffer: Vec::new(),
            output: Vec::new(),
        }
    }

    pub fn stdin_stdout(&mut self) -> (MockStdin, MockStdout) {
        let inp = Arc::new(Mutex::new(self));
        let out = inp.clone();
        (MockStdin { term: inp, temp_buf: Vec::new() }, MockStdout { term: out })
    }

    pub fn write_stdin(mut self, str: &str) -> Self {
        let mut line = VecDeque::from(str.as_bytes().to_vec());
        line.push_back(13);
        self.actions.push_back(TermAction::Write(line));
        self
    }

    pub fn wait_stdout(mut self) -> Self {
        self.actions.push_back(TermAction::Read);
        self
    }

    pub fn expect_stdout(mut self, str: &str) -> Self {
        self.actions.push_back(TermAction::Expect(str.to_owned()));
        self
    }

    pub fn get_stdout(&self) -> &Vec<String> {
        &self.output
    }
}

impl Read for MockTerminal {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut offset: usize = 0;
        while offset < buf.len() {
            if let Some(next) = stdin(self.actions.front_mut()) {
                while offset < buf.len() && !next.is_empty() {
                    buf[offset] = next.pop_front().unwrap();
                    offset += 1;
                }
                if next.is_empty() {
                    self.actions.pop_front();
                }
            } else {
                break;
            }
        }
        Ok(offset)
    }
}

impl BufRead for MockTerminal {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if let Some(next) = stdin(self.actions.front_mut()) {
            for b in next.bytes() {
                self.stdin_buffer.push_back(b.unwrap());
            }
            self.actions.pop_front();
        }
        self.stdin_buffer.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.stdin_buffer.consume(amt)
    }
}

impl Write for MockTerminal {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for c in buf {
            self.stdout_buffer.push(*c);
            if *c == 10u8 {
                self.output.push(std::str::from_utf8(self.stdout_buffer.as_slice()).unwrap().to_owned());
                self.stdout_buffer.clear();
                match self.actions.front() {
                    Some(TermAction::Read) => {
                        self.actions.pop_front();
                    },
                    Some(TermAction::Expect(str)) => {
                        assert_eq!(self.output.last().unwrap(), str);
                        self.actions.pop_front();
                    },
                    _ => {},
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.stdout_buffer.is_empty() {
            self.output.push(std::str::from_utf8(self.stdout_buffer.as_slice()).unwrap().to_owned());
            self.stdout_buffer.clear();
        }
        match self.actions.front() {
            Some(TermAction::Read) => {
                self.actions.pop_front();
            },
            Some(TermAction::Expect(str)) => {
                assert_eq!(self.output.last().unwrap(), str);
                self.actions.pop_front();
            },
            _ => {},
        }
        Ok(())
    }
}

impl <'a> Read for MockStdin<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.term.lock().unwrap().read(buf)
    }
}

impl <'a> BufRead for MockStdin<'a> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.temp_buf.extend_from_slice(self.term.lock().unwrap().fill_buf()?);
        Ok(&self.temp_buf)
    }

    fn consume(&mut self, amt: usize) {
        self.temp_buf.clear();
        self.term.lock().unwrap().consume(amt)
    }
}

impl <'a> Write for MockStdout<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.term.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.term.lock().unwrap().flush()
    }
}

fn stdin(act: Option<&mut TermAction>) -> Option<&mut VecDeque<u8>> {
    match act {
        Some(TermAction::Write(bytes)) => Some(bytes),
        _ => None,
    }
}
