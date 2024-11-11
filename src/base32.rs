struct BitBuffer {
    bit_offset: u8,
    bytes: Vec<u8>,
}

impl BitBuffer {
    fn new() -> Self {
        BitBuffer { bit_offset: 0u8, bytes: Vec::new() }
    }

    fn write(&mut self, data: u8, bits: u8) {
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

    fn into_bytes(mut self) -> Vec<u8> {
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
    for c in base32.to_ascii_uppercase().chars() {
        let bits = match c {
            'A' ..= 'Z' => { let b: u8 = c.try_into().unwrap(); b - capital_a }
            '2' ..= '7' => { let b: u8 = c.try_into().unwrap(); b - digit_2_minus_26 },
            '=' => break,
            _ => return None,
        };
        buffer.write(bits, 5);
    };
    Some(buffer.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_decodes_valid_base32() {
        assert_eq!(
            decode("NBSWY3DP"),
            Some("hello".as_bytes().to_vec()),
        );
        assert_eq!(
            decode("OBXXIYLUN4======"),
            Some("potato".as_bytes().to_vec()),
        );
        assert_eq!(
            decode("OBXXIYLUN4"),
            Some("potato".as_bytes().to_vec()),
        );
        assert_eq!(
            decode(""),
            Some("".as_bytes().to_vec()),
        );
    }

    #[test]
    fn decode_handles_lowercase_base32() {
        assert_eq!(
            decode("nbswy3dp"),
            Some("hello".as_bytes().to_vec()),
        );
        assert_eq!(
            decode("nbSWy3Dp"),
            Some("hello".as_bytes().to_vec()),
        );
        assert_eq!(
            decode("obxxiylun4======"),
            Some("potato".as_bytes().to_vec()),
        );
        assert_eq!(
            decode("obxxiylun4"),
            Some("potato".as_bytes().to_vec()),
        );
    }

    #[test]
    fn decode_returns_none_on_invalid_char() {
        assert_eq!(
            decode("NBSWY3D?"),
            None,
        );
        assert_eq!(
            decode("1BSWY3DP"),
            None,
        );
    }

    #[test]
    fn bit_buffer_writes_left_to_right() {
        let mut buf = BitBuffer::new();
        buf.write(1u8, 1);
        buf.write(64u8, 7);
        assert_eq!(
            buf.into_bytes(),
            vec![0xc0],
        );
    }

    #[test]
    fn bit_buffer_properly_handles_writes_across_byte_boundaries() {
        let mut buf = BitBuffer::new();
        buf.write(1u8, 4);
        buf.write(72u8, 8);
        buf.write(1u8, 4);
        assert_eq!(
            buf.into_bytes(),
            vec![0x14, 0x81],
        );
    }

    #[test]
    fn bit_buffer_discards_incomplete_bytes() {
        let mut buf = BitBuffer::new();
        buf.write(1u8, 1);
        assert_eq!(
            buf.into_bytes(),
            vec![] as Vec<u8>,
        );

        let mut buf = BitBuffer::new();
        buf.write(1u8, 1);
        buf.write(0u8, 7);
        buf.write(1u8, 1);
        assert_eq!(
            buf.into_bytes(),
            vec![0x80],
        );
    }
}
