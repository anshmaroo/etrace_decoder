pub const FMT_MASK: u8 = 0b0000_0011;
pub const SUBFMT_MASK: u8 = 0b0000_1100;

#[derive(Debug, Clone, PartialEq, Eq)]

pub enum UInt {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}

macro_rules! impl_tryfrom_uint {
    ($($t:ty, $variant:ident),*) => {
        $(
            impl std::convert::TryFrom<UInt> for $t {
                type Error = ();

                fn try_from(value: UInt) -> Result<Self, Self::Error> {
                    if let UInt::$variant(v) = value {
                        Ok(v)
                    } else {
                        Err(())
                    }
                }
            }
        )*
    };
}

impl_tryfrom_uint!(
    u8, U8,
    u16, U16,
    u32, U32,
    u64, U64,
    u128, U128
);

impl UInt {
    pub fn to_u32(&self) -> Option<u32> {
        match self {
            UInt::U8(v) => Some(*v as u32),
            UInt::U16(v) => Some(*v as u32),
            UInt::U32(v) => Some(*v),
            UInt::U64(v) => u32::try_from(*v).ok(),
            UInt::U128(v) => u32::try_from(*v).ok(),
        }
    }
}

#[derive(Debug)]
pub enum Fmt {
    Fmt_3 = 0b11, // sync, trap, context, support
    Fmt_2 = 0b10, // address
    Fmt_1 = 0b01, // branch map
    Fmt_0 = 0b00, // optional
}

impl From<UInt> for Fmt {
    fn from(value: UInt) -> Self {
        match <UInt as TryInto<u8>>::try_into(value).unwrap() {
            0b00 => Fmt::Fmt_0,
            0b01 => Fmt::Fmt_1,
            0b10 => Fmt::Fmt_2,
            0b11 => Fmt::Fmt_3,
            _ => panic!("Invalid format value"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subfmt {
    Start = 0b00,
    Trap = 0b01,
    Context = 0b10,
    Support = 0b11,
}

impl From<UInt> for Subfmt {
    fn from(value: UInt) -> Self {
        match <UInt as TryInto<u8>>::try_into(value).unwrap() {
            0b00 => Subfmt::Start,
            0b01 => Subfmt::Trap,
            0b10 => Subfmt::Context,
            0b11 => Subfmt::Support,
            _ => panic!("Invalid subformat value"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privilege {
    P_U = 0,
    P_S = 1,
    // 2 is reserved
    P_M = 3,
    // 4-7 is optional and unused for now
    P_D = 4,
    P_VU = 5,
    P_VS = 6,
    // 7 is reserved
}

impl From<UInt> for Privilege {
    fn from(value: UInt) -> Self {
        match <UInt as TryInto<u8>>::try_into(value).unwrap() {
            1 => Privilege::P_U,
            2 => Privilege::P_S,
            3 => Privilege::P_M,
            4 => Privilege::P_D,
            5 => Privilege::P_VU,
            6 => Privilege::P_VS,
            _ => panic!("Invalid privilege value"),
        }
    }
}

// field widths

pub const FMT_WIDTH: usize = 2;
pub const SUBFMT_WIDTH: usize = 2;
pub const BRANCH_WIDTH: usize = 1;
pub const PRIVILEGE_WIDTH: usize = 3;
pub const TIME_WIDTH: usize = 64;
pub const CONTEXT_WIDTH: usize = 0xffff; // unimplemented
pub const ECAUSE_WIDTH: usize = 8;
pub const INTERRUPT_WIDTH: usize = 1;
pub const THADDR_WIDTH: usize = 1;
pub const ADDRESS_WIDTH: usize = 63;
pub const TVAL_WIDTH: usize = 64;
pub const NOTIFY_WIDTH: usize = 1;
pub const BRANCHES_WIDTH: usize = 5;
