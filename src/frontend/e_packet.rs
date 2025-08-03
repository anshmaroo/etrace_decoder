use anyhow::Result;
use bit_vec::*;
use log::trace;
use std::fs::File;
use std::io::{BufReader, Error, Read};
use std::num::NonZero;

use crate::frontend::encodings::*;

const MAX_PACKET_SIZE: usize = 512;

#[derive(Debug)]
pub enum Packet {
    // FIXME - need to implement all fields
    FMT_3 {
        fmt: Fmt,
        subfmt: Subfmt,
        branch: Option<bool>,
        privilege: Option<Privilege>,
        time: Option<u64>,
        ecause: Option<u8>,
        interrupt: Option<bool>,
        thaddr: Option<bool>,
        address: Option<u64>,
        tval: Option<u64>,
    },
    FMT_2 {
        fmt: Fmt,
        address: u64,
        notify: bool,
        updiscon: bool,
    },
    FMT_1 {
        fmt: Fmt,
        branches: u8,
        branch_map: u32,
        address: u64,
        notify: bool,
        updiscon: bool,
    },

    None,
}

enum DecodeError {}

fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn read_u8(stream: &mut BufReader<File>) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16(stream: &mut BufReader<File>) -> Result<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn parse_bits(vector: &mut BitVec, num_bits: usize) -> UInt {
    assert!(
        num_bits <= 128 && num_bits <= vector.len(),
        "Invalid bit count"
    );

    let mut value: u128 = 0;
    for i in 0..num_bits {
        value = value | (vector[i] as u128) << i;
    }
    *vector = vector.split_off(num_bits);

    match num_bits {
        0..=8 => UInt::U8(value as u8),
        9..=16 => UInt::U16(value as u16),
        17..=32 => UInt::U32(value as u32),
        33..=64 => UInt::U64(value as u64),
        _ => UInt::U128(value),
    }
}

pub fn read_packet(stream: &mut BufReader<File>) -> Result<Packet> {
    let num_bytes_compressed: u16 = read_u8(stream)? as u16;
    let num_bits_uncompressed: u16 = read_u16(stream)?;
    let mut buf = vec![0u8; num_bytes_compressed as usize];

    stream.read_exact(&mut buf)?;

    // reverse each byte (bitvector will, as a result, be LSB first)
    for i in 0..buf.len() {
        buf[i] = u8::reverse_bits(buf[i]);
    }

    // convert the compressed packet to a bit vector. add (or remove) padding to reconstruct the original packet
    let mut packet = BitVec::from_bytes(&buf);
    if (num_bits_uncompressed >= num_bytes_compressed * 8) {
        let padding_length = (num_bits_uncompressed - (num_bytes_compressed * 8)) as usize;
        let mut padding = BitVec::with_capacity(padding_length);

        let sign = packet.get((num_bytes_compressed * 8 - 1) as usize);
        if let Some(_sign) = sign {
            for i in 0..padding_length {
                padding.push(_sign);
            }
        }

        packet.append(&mut padding);
    } else {
        packet.truncate(num_bits_uncompressed as usize);
    }

    // start parsing
    let fmt: Fmt = Fmt::from(parse_bits(&mut packet, FMT_WIDTH));

    match fmt {
        Fmt::Fmt_3 => {
            let subfmt = Subfmt::from(parse_bits(&mut packet, SUBFMT_WIDTH));

            match subfmt {
                Subfmt::Start => {
                    let branch: u8 = parse_bits(&mut packet, BRANCH_WIDTH).try_into().unwrap();
                    let privilege: Privilege =
                        parse_bits(&mut packet, PRIVILEGE_WIDTH).try_into().unwrap();
                    let time: u64 = parse_bits(&mut packet, TIME_WIDTH).try_into().unwrap();
                    let address: u64 = parse_bits(&mut packet, ADDRESS_WIDTH).try_into().unwrap();
                    Ok(Packet::FMT_3 {
                        fmt: (fmt),
                        subfmt: (subfmt),
                        branch: Some(branch > 0),
                        privilege: Some(privilege),
                        time: Some(time),
                        ecause: (None),
                        interrupt: (None),
                        thaddr: (None),
                        address: Some(address << 1),
                        tval: (None),
                    })
                }
                Subfmt::Trap => {
                    let branch: u8 = parse_bits(&mut packet, BRANCH_WIDTH).try_into().unwrap();
                    let privilege: Privilege =
                        parse_bits(&mut packet, PRIVILEGE_WIDTH).try_into().unwrap();
                    let time: u64 = parse_bits(&mut packet, TIME_WIDTH).try_into().unwrap();
                    let ecause: u8 = parse_bits(&mut packet, ECAUSE_WIDTH).try_into().unwrap();
                    let interrupt: u8 =
                        parse_bits(&mut packet, INTERRUPT_WIDTH).try_into().unwrap();
                    let thaddr: u8 = parse_bits(&mut packet, THADDR_WIDTH).try_into().unwrap();
                    let address: u64 = parse_bits(&mut packet, ADDRESS_WIDTH).try_into().unwrap();
                    let tval: u64 = parse_bits(&mut packet, TVAL_WIDTH).try_into().unwrap();
                    Ok(Packet::FMT_3 {
                        fmt: (fmt),
                        subfmt: (subfmt),
                        branch: Some(branch > 0),
                        privilege: Some(privilege),
                        time: Some(time),
                        ecause: Some(ecause),
                        interrupt: Some(interrupt > 0),
                        thaddr: Some(thaddr > 0),
                        address: Some(address << 1),
                        tval: Some(tval),
                    })
                }
                Subfmt::Context => {
                    let privilege: Privilege =
                        parse_bits(&mut packet, PRIVILEGE_WIDTH).try_into().unwrap();
                    let time: u64 = parse_bits(&mut packet, TIME_WIDTH).try_into().unwrap();

                    Ok(Packet::FMT_3 {
                        fmt: (fmt),
                        subfmt: (subfmt),
                        branch: (None),
                        privilege: Some(privilege),
                        time: Some(time),
                        ecause: (None),
                        interrupt: (None),
                        thaddr: (None),
                        address: (None),
                        tval: (None),
                    })
                }
                Subfmt::Support => todo!(),
            }
        }
        Fmt::Fmt_2 => {
            let address: u64 = parse_bits(&mut packet, ADDRESS_WIDTH).try_into().unwrap();
            let notify: u8 = parse_bits(&mut packet, NOTIFY_WIDTH).try_into().unwrap();
            let updiscon: u8 = parse_bits(&mut packet, UPDISCON_WIDTH).try_into().unwrap();

            Ok(Packet::FMT_2 {
                fmt: (fmt),
                address: (address << 1),
                notify: (notify > 0),
                updiscon: (updiscon > 0)
            })
        }
        Fmt::Fmt_1 => {
            let branches: u8 = parse_bits(&mut packet, BRANCHES_WIDTH).try_into().unwrap();
            let mut branch_map_width: usize = if (branches <= 3) {
                3
            } else if (branches <= 7) {
                7
            } else if (branches <= 15) {
                15
            } else if (branches <= 31) {
                31
            } else {
                0
            };

            let branch_map: u32 = parse_bits(&mut packet, branch_map_width).to_u32().unwrap();
            let address: u64 = parse_bits(&mut packet, ADDRESS_WIDTH).try_into().unwrap();
            let notify: u8 = parse_bits(&mut packet, NOTIFY_WIDTH).try_into().unwrap();
            let updiscon: u8 = parse_bits(&mut packet, UPDISCON_WIDTH).try_into().unwrap();

            Ok(Packet::FMT_1 {
                fmt: (fmt),
                branches: (branches),
                branch_map: (branch_map),
                address: (address << 1),
                notify: (notify > 0),
                updiscon: (updiscon > 0)
            })
        }
        Fmt::Fmt_0 => todo!(),
    }
}
