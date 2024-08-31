struct BitBuffer {
    bit_offset: u8,
    bytes: Vec<u8>,
}

impl BitBuffer {
    fn new() -> Self {
        BitBuffer { bit_offset: 0u8, bytes: Vec::new() }
    }

    fn write(&mut self, data: u8, bits: u8) -> () {
        assert!(bits <= 8);
        if self.bit_offset + bits > 8 {
            let second_write_bits = (self.bit_offset + bits) % 8;
            let first_write_bits = bits - second_write_bits;
            self.write(data >> second_write_bits, first_write_bits);
            self.write(data, second_write_bits);
            return;
        }
        if self.bit_offset == 0 {
            self.bytes.push(data << (8 - bits));
            self.bit_offset = bits;
        } else {
            let byte_offset = self.bytes.len() - 1;
            self.bytes[byte_offset] |= (data & (0xffu8 >> (8 - bits))) << (8 - bits - self.bit_offset);
            self.bit_offset = (self.bit_offset + bits) % 8;
        }
    }

    fn to_bytes(mut self) -> Vec<u8> {
        if self.bit_offset != 0 {
            self.bytes.pop();
            self.bytes
        } else {
            self.bytes
        }
    }
}

pub fn decode(base32: &str) -> Option<Vec<u8>> {
    let capital_a = 65u8;
    let digit_2_minus_26 = 24u8;
    let mut buffer = BitBuffer::new();
    for c in base32.chars() {
        let bits = match c {
            'A' ..= 'Z' => { let b: u8 = c.try_into().unwrap(); b - capital_a }
            '2' ..= '7' => { let b: u8 = c.try_into().unwrap(); b - digit_2_minus_26 },
            '=' => break,
            _ => return None,
        };
        buffer.write(bits, 5);
    };
    Some(buffer.to_bytes())
}
