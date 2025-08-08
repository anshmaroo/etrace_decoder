extern crate bus;
extern crate clap;
extern crate env_logger;
extern crate gcno_reader;
extern crate log;
extern crate object;
extern crate rvdasm;
mod frontend {
    pub mod bp_double_saturating_counter;
    pub mod br_mode;
    pub mod c_header;
    pub mod e_packet;
    pub mod encodings;
    pub mod f_header;
    pub mod packet;
    pub mod trap_type;
}
mod backend {
    pub mod abstract_receiver;
    pub mod afdo_receiver;
    pub mod event;
    pub mod foc_receiver;
    pub mod gcda_receiver;
    pub mod speedscope_receiver;
    pub mod stack_unwinder;
    pub mod stats_receiver;
    pub mod txt_receiver;
    pub mod vbb_receiver;
    pub mod vpp_receiver;
}

use frontend::f_header::FHeader;

// file IO
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
// collections
use std::collections::HashMap;
// argparse dependency
use clap::Parser;
// objdump dependency
use object::elf::SHF_EXECINSTR;
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags};
use rvdasm::disassembler::*;
use rvdasm::insn::*;
// bus dependency
use bus::Bus;
use std::thread;
// frontend dependency
use frontend::bp_double_saturating_counter::BpDoubleSaturatingCounter;
use frontend::br_mode::BrMode;
// backend dependency
use backend::abstract_receiver::AbstractReceiver;
use backend::afdo_receiver::AfdoReceiver;
use backend::event::{Entry, Event};
use backend::foc_receiver::FOCReceiver;
use backend::gcda_receiver::GcdaReceiver;
use backend::speedscope_receiver::SpeedscopeReceiver;
use backend::stats_receiver::StatsReceiver;
use backend::txt_receiver::TxtReceiver;
use backend::vbb_receiver::VBBReceiver;
use backend::vpp_receiver::VPPReceiver;
// error handling
use anyhow::Result;
// logging
use log::{debug, trace};

const BRANCH_OPCODES: &[&str] = &[
    "beq", "bge", "bgeu", "blt", "bltu", "bne", "beqz", "bnez", "bgez", "blez", "bltz", "bgtz",
    "bgt", "ble", "bgtu", "bleu", "c.beqz", "c.bnez", "c.bltz", "c.bgez",
];
const IJ_OPCODES: &[&str] = &["jal", "j", "call", "tail", "c.j", "c.jal"];
const UJ_OPCODES: &[&str] = &["jalr", "jr", "c.jr", "c.jalr", "ret"];
const BUS_SIZE: usize = 1024;

#[derive(Clone, Parser)]
#[command(
    name = "trace-decoder",
    version = "0.1.0",
    about = "Decode trace files"
)]
struct Args {
    // path to the encoded trace file
    #[arg(short, long)]
    encoded_trace: String,
    // path to the binary file
    #[arg(short, long)]
    binary: String,
    // path to the decoded trace file
    #[arg(short, long, default_value_t = String::from("trace.dump"))]
    decoded_trace: String,
    // branch mode
    #[arg(long, default_value_t = 0)]
    br_mode: u64,
    // branch prediction number of entries
    #[arg(long, default_value_t = 1024)]
    bp_entries: u64,
    // print the timestamp in the decoded trace file
    #[arg(short, long, default_value_t = false)]
    timestamp: bool,
    // output the decoded trace in stats format
    #[arg(long, default_value_t = false)]
    to_stats: bool,
    // output the decoded trace in text format
    #[arg(long, default_value_t = true)]
    to_txt: bool,
    // output the decoded trace in afdo format
    #[arg(long, default_value_t = false)]
    to_afdo: bool,
    // path to the gcno file, must be provided if to_afdo is true
    #[arg(long, default_value_t = String::from(""))]
    gcno: String,
    // output the decoded trace in gcda format
    #[arg(long, default_value_t = false)]
    to_gcda: bool,
    // output the decoded trace in speedscope format
    #[arg(long, default_value_t = false)]
    to_speedscope: bool,
    // output the decoded trace in vpp format
    #[arg(long, default_value_t = false)]
    to_vpp: bool,
    // output the decoded trace in foc format
    #[arg(long, default_value_t = false)]
    to_foc: bool,
    // output the decoded trace in vbb format
    #[arg(long, default_value_t = false)]
    to_vbb: bool,
}

fn refund_addr(addr: u64) -> u64 {
    addr << 1
}

fn step_bb_until(
    pc: u64,
    insn_map: &HashMap<u64, Insn>,
    end_pc_offset: u64,
    bus: &mut Bus<Entry>,
) -> u64 {
    let mut pc = pc;
    loop {
        if let Some(insn) = insn_map.get(&pc) {
            // bus.broadcast(Entry::new_insn(insn, pc));
            if insn.is_direct_jump() {
                // use immediate
                bus.broadcast(Entry::new_insn(insn, pc));
                pc = pc.wrapping_add(insn.get_imm().unwrap().get_val_signed_imm() as u64);
            } else if insn.is_branch() {
                break;
            } else if insn.is_indirect_jump() {
                // use the offset and break
                bus.broadcast(Entry::new_insn(insn, pc));
                pc = pc.wrapping_add(end_pc_offset);
                break;
            } else {
                bus.broadcast(Entry::new_insn(insn, pc));
                pc = pc.wrapping_add(insn.len as u64);
            }
        } else {
            break;
        }
    }

    pc
}

fn step_bb_branch_map(
    pc: u64,
    insn_map: &HashMap<u64, Insn>,
    end_pc_offset: u64,
    branch_map: u32,
    branches: u8,
    with_address: bool,
    bus: &mut Bus<Entry>,
) -> u64 {
    let mut pc = pc;
    let mut local_branches = branches;
    loop {
        if (local_branches == 0 && !with_address) {
            break;
        }
        if let Some(insn) = insn_map.get(&pc) {
            if insn.is_direct_jump() {
                bus.broadcast(Entry::new_insn(insn, pc));
                pc = pc.wrapping_add(insn.get_imm().unwrap().get_val_signed_imm() as u64);
            } else if insn.is_branch() {
                // print!("branch at address: {:#16x}. ", pc);
                if (local_branches > 0) {
                    let taken = (branch_map & ((1 as u32) << (local_branches - 1))) > 0;
                    // println!("branch map: {:b}, branch #: {}, taken: {}", branch_map, local_branches, taken);
                    bus.broadcast(Entry::new_insn(insn, pc));
                    if (taken) {
                        pc = pc.wrapping_add(insn.get_imm().unwrap().get_val_signed_imm() as u64);
                    } else {
                        pc = pc.wrapping_add(insn.len as u64);
                    }

                    local_branches -= 1;
                } else {
                    break;
                }
            } else if insn.is_indirect_jump() {
                assert_eq!(with_address, true);
                bus.broadcast(Entry::new_insn(insn, pc));
                pc = pc.wrapping_add(end_pc_offset);
                break;
                
            } else {
                bus.broadcast(Entry::new_insn(insn, pc));
                pc = pc.wrapping_add(insn.len as u64);
            }
        } else {
            break;
        }
    }
    // println!();
    pc
}

// frontend decoding packets and pushing entries to the bus
fn trace_decoder(args: &Args, mut bus: Bus<Entry>) -> Result<()> {
    let mut elf_file = File::open(args.binary.clone())?;
    let mut elf_buffer = Vec::new();
    elf_file.read_to_end(&mut elf_buffer)?;
    let elf = object::File::parse(&*elf_buffer)?;
    let elf_arch = elf.architecture();

    let xlen = if elf_arch == object::Architecture::Riscv64 {
        Xlen::XLEN64
    } else if elf_arch == object::Architecture::Riscv32 {
        Xlen::XLEN32
    } else {
        panic!("Unsupported architecture: {:?}", elf_arch);
    };

    let dasm = Disassembler::new(xlen);

    let mut insn_map = HashMap::new();
    for section in elf.sections() {
        if let object::SectionFlags::Elf { sh_flags } = section.flags() {
            if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                let addr = section.address();
                let data = section.data()?;
                let sec_map = dasm.disassemble_all(&data, addr);
                debug!(
                    "section `{}` @ {:#x}: {} insns",
                    section.name().unwrap_or("<unnamed>"),
                    addr,
                    sec_map.len()
                );
                insn_map.extend(sec_map);
            }
        }
    }
    if insn_map.is_empty() {
        return Err(anyhow::anyhow!(
            "No executable instructions found in ELF file"
        ));
    }
    debug!("[main] found {} instructions", insn_map.len());

    let encoded_trace_file = File::open(args.encoded_trace.clone())?;
    let mut encoded_trace_reader: BufReader<File> = BufReader::new(encoded_trace_file);

    let mut bp_counter = BpDoubleSaturatingCounter::new(args.bp_entries);

    let br_mode = BrMode::from(args.br_mode);
    let mode_is_predict = br_mode == BrMode::BrPredict || br_mode == BrMode::BrHistory;

    let packet = frontend::e_packet::read_packet(&mut encoded_trace_reader)?;
    let mut packet_count = 0;
    let mut pc: u64;
    let mut timestamp: u64;

    let mut previous_branches: u8 = 0;
    let mut remaining_branches: u8 = 0;

    match packet {
        frontend::e_packet::Packet::FMT_3 {
            fmt,
            subfmt,
            branch,
            privilege,
            time,
            ecause,
            interrupt,
            thaddr,
            address,
            tval,
        } => {
            pc = address.unwrap();
            timestamp = time.unwrap();
            bus.broadcast(Entry::new_timed_event(Event::Start, timestamp, pc, 0));
        }
        _ => todo!(),
    }

    while let Ok(packet) = frontend::e_packet::read_packet(&mut encoded_trace_reader) {
        packet_count += 1;
        // special handling for the last packet, should be unlikely hinted
        trace!("[{}]: packet: {:?}", packet_count, packet);

        match packet {
            frontend::e_packet::Packet::FMT_3 {
                fmt,
                subfmt,
                branch,
                privilege,
                time,
                ecause,
                interrupt,
                thaddr,
                address,
                tval,
            } => match subfmt {
                frontend::encodings::Subfmt::Start => {
                    bus.broadcast(Entry::new_timed_event(Event::Start, timestamp, pc, 0))
                }
                frontend::encodings::Subfmt::Trap => todo!(),
                frontend::encodings::Subfmt::Context => todo!(),
                frontend::encodings::Subfmt::Support => todo!(),
            },
            frontend::e_packet::Packet::FMT_2 {
                fmt,
                address,
                notify,
                updiscon,
            } => {
                pc = step_bb_until(pc, &insn_map, address, &mut bus);
            }
            frontend::e_packet::Packet::FMT_1 {
                fmt,
                branches,
                branch_map,
                address,
                notify,
                updiscon,
            } => {
                // println!("packet: {} at pc = {:#16x}",packet_count + 1, pc);
                // use the branch map to handle branch decisions
                if (branches == 0) {
                    pc = step_bb_branch_map(pc, &insn_map, address, branch_map, 31, false, &mut bus)
                } else {
                    pc = step_bb_branch_map(pc, &insn_map, address, branch_map, branches, true, &mut bus)
                }
                
            }
            frontend::e_packet::Packet::None => todo!(),
        }

        // print!("Press Enter to continue...");
        // io::stdout().flush().unwrap(); // Ensure the prompt is displayed

        // let mut buffer = String::new();
        // io::stdin()
        //     .read_line(&mut buffer)
        //     .expect("Failed to read line");
    }

    drop(bus);
    println!("[Success] Decoded {} packets", packet_count);

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let mut bus: Bus<Entry> = Bus::new(BUS_SIZE);
    let mut receivers: Vec<Box<dyn AbstractReceiver>> = vec![];

    // add a receiver to the bus for stats output
    if args.to_stats {
        let encoded_trace_file = File::open(args.encoded_trace.clone())?;
        // get the file size
        let file_size = encoded_trace_file.metadata()?.len();
        // close the file
        drop(encoded_trace_file);
        let stats_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(StatsReceiver::new(
            stats_bus_endpoint,
            BrMode::from(args.br_mode),
            file_size,
        )));
    }

    // add a receiver to the bus for txt output
    if args.to_txt {
        let txt_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(TxtReceiver::new(txt_bus_endpoint)));
    }

    if args.to_afdo {
        let afdo_bus_endpoint = bus.add_rx();
        let mut elf_file = File::open(args.binary.clone())?;
        let mut elf_buffer = Vec::new();
        elf_file.read_to_end(&mut elf_buffer)?;
        let elf = object::File::parse(&*elf_buffer)?;
        receivers.push(Box::new(AfdoReceiver::new(
            afdo_bus_endpoint,
            elf.entry().clone(),
        )));
        drop(elf_file);
    }

    if args.to_gcda {
        let gcda_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(GcdaReceiver::new(
            gcda_bus_endpoint,
            args.gcno.clone(),
            args.binary.clone(),
        )));
    }

    if args.to_speedscope {
        let speedscope_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(SpeedscopeReceiver::new(
            speedscope_bus_endpoint,
            args.binary.clone(),
        )));
    }

    if args.to_vpp {
        let vpp_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(VPPReceiver::new(
            vpp_bus_endpoint,
            args.binary.clone(),
            args.br_mode == 0,
        )));
    }

    if args.to_foc {
        let foc_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(FOCReceiver::new(
            foc_bus_endpoint,
            args.binary.clone(),
        )));
    }

    if args.to_vbb {
        let vbb_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(VBBReceiver::new(vbb_bus_endpoint)));
    }

    let frontend_handle = thread::spawn(move || trace_decoder(&args, bus));
    let receiver_handles: Vec<_> = receivers
        .into_iter()
        .map(|mut receiver| thread::spawn(move || receiver.try_receive_loop()))
        .collect();

    // Handle frontend thread
    match frontend_handle.join() {
        Ok(result) => result?,
        Err(e) => {
            // still join the receivers
            for handle in receiver_handles {
                handle.join().unwrap();
            }
            println!("frontend thread panicked: {:?}", e);
            return Err(anyhow::anyhow!("Frontend thread panicked: {:?}", e));
        }
    }

    // Handle receiver threads
    for (i, handle) in receiver_handles.into_iter().enumerate() {
        if let Err(e) = handle.join() {
            return Err(anyhow::anyhow!("Receiver thread {} panicked: {:?}", i, e));
        }
    }

    Ok(())
}
