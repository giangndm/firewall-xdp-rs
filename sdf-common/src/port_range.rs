#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PortRange(pub u16, pub u16);

impl From<u32> for PortRange {
    fn from(value: u32) -> Self {
        Self((value >> 16) as u16, value as u16)
    }
}

impl From<PortRange> for u32 {
    fn from(value: PortRange) -> Self {
        ((value.0 as u32) << 16) | (value.1 as u32)
    }
}

#[cfg(test)]
mod test {
    use crate::PortRange;

    #[test]
    fn test_convert() {
        assert_eq!(u32::from(PortRange(0x1234, 0x5678)), 0x12345678 as u32);
        assert_eq!(PortRange::from(0x12345678), PortRange(0x1234, 0x5678));
    }
}
