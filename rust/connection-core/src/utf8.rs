//! Private allocation-free incremental UTF-8 validation.

use crate::Utf8Failure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirstContinuationRule {
    Any,
    NoOverlong,
    NoSurrogate,
    InUnicodeRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Utf8Validator {
    offset: u64,
    sequence_start: u64,
    remaining: u8,
    next_min: u8,
    next_max: u8,
    first_rule: FirstContinuationRule,
}

impl Utf8Validator {
    pub(crate) const fn new() -> Self {
        Self {
            offset: 0,
            sequence_start: 0,
            remaining: 0,
            next_min: 0x80,
            next_max: 0xbf,
            first_rule: FirstContinuationRule::Any,
        }
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<(), Utf8Failure> {
        for &byte in bytes {
            if self.remaining == 0 {
                self.start(byte)?;
            } else {
                self.continue_scalar(byte)?;
            }
            self.offset = self.offset.saturating_add(1);
        }
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<(), Utf8Failure> {
        if self.remaining == 0 {
            Ok(())
        } else {
            Err(Utf8Failure::TruncatedSequence {
                length: self.offset,
                remaining: self.remaining,
            })
        }
    }

    fn start(&mut self, byte: u8) -> Result<(), Utf8Failure> {
        self.sequence_start = self.offset;
        match byte {
            0x00..=0x7f => {}
            0x80..=0xbf => {
                return Err(Utf8Failure::UnexpectedContinuation {
                    offset: self.offset,
                    byte,
                });
            }
            0xc0..=0xc1 => {
                return Err(Utf8Failure::OverlongEncoding {
                    offset: self.offset,
                });
            }
            0xc2..=0xdf => self.expect(1, 0x80, 0xbf, FirstContinuationRule::Any),
            0xe0 => self.expect(2, 0xa0, 0xbf, FirstContinuationRule::NoOverlong),
            0xe1..=0xec | 0xee..=0xef => {
                self.expect(2, 0x80, 0xbf, FirstContinuationRule::Any);
            }
            0xed => self.expect(2, 0x80, 0x9f, FirstContinuationRule::NoSurrogate),
            0xf0 => self.expect(3, 0x90, 0xbf, FirstContinuationRule::NoOverlong),
            0xf1..=0xf3 => self.expect(3, 0x80, 0xbf, FirstContinuationRule::Any),
            0xf4 => self.expect(3, 0x80, 0x8f, FirstContinuationRule::InUnicodeRange),
            0xf5..=0xf7 => {
                return Err(Utf8Failure::CodePointOutOfRange {
                    offset: self.offset,
                });
            }
            0xf8..=0xff => {
                return Err(Utf8Failure::InvalidLeadingByte {
                    offset: self.offset,
                    byte,
                });
            }
        }
        Ok(())
    }

    fn expect(&mut self, remaining: u8, min: u8, max: u8, rule: FirstContinuationRule) {
        self.remaining = remaining;
        self.next_min = min;
        self.next_max = max;
        self.first_rule = rule;
    }

    fn continue_scalar(&mut self, byte: u8) -> Result<(), Utf8Failure> {
        if !(self.next_min..=self.next_max).contains(&byte) {
            return Err(match self.first_rule {
                FirstContinuationRule::NoOverlong if (0x80..self.next_min).contains(&byte) => {
                    Utf8Failure::OverlongEncoding {
                        offset: self.sequence_start,
                    }
                }
                FirstContinuationRule::NoSurrogate
                    if (self.next_max.saturating_add(1)..=0xbf).contains(&byte) =>
                {
                    Utf8Failure::SurrogateCodePoint {
                        offset: self.sequence_start,
                    }
                }
                FirstContinuationRule::InUnicodeRange
                    if (self.next_max.saturating_add(1)..=0xbf).contains(&byte) =>
                {
                    Utf8Failure::CodePointOutOfRange {
                        offset: self.sequence_start,
                    }
                }
                _ => Utf8Failure::InvalidContinuation {
                    offset: self.offset,
                    byte,
                },
            });
        }
        self.remaining -= 1;
        self.next_min = 0x80;
        self.next_max = 0xbf;
        self.first_rule = FirstContinuationRule::Any;
        Ok(())
    }
}
