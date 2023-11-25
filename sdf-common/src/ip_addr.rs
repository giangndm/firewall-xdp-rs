#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct IpV4Addr(pub [u8; 4]);

impl From<u32> for IpV4Addr {
    fn from(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
}

impl From<IpV4Addr> for u32 {
    fn from(value: IpV4Addr) -> Self {
        u32::from_be_bytes(value.0)
    }
}

#[cfg(test)]
mod test {
    use crate::IpV4Addr;

    #[test]
    fn convert_u32() {
        assert_eq!(u32::from(IpV4Addr([1, 2, 3, 4])), 0x01020304);
        assert_eq!(IpV4Addr::from(0x01020304), IpV4Addr([1, 2, 3, 4]));
    }
}
