/* Copyright (c) 2023 BlackBerry Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
use std::io::Error;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

extern crate libbpf_rs;
use libbpf_rs::{MapFlags, RingBufferBuilder};

extern crate clap;
use clap::Parser;

extern crate signal_hook;
use signal_hook::consts::signal::SIGUSR1;
use signal_hook::iterator::Signals;

#[path = "bpf/.output/stack_pivot_poc.skel.rs"]
mod stack_pivot_poc;
use stack_pivot_poc::*;

// would be nice if we could pull this in directly from utils.h
const ERR_LEVEL_WARNING: i32 = 1;
const ERR_LEVEL_ALERT: i32 = 2;

const ERR_TYPE_NONE: i32 = 0;
const ERR_TYPE_UNK_STACK: i32 = (ERR_LEVEL_WARNING << 12) | 1;
const ERR_TYPE_STACK_PIVOT: i32 =  (ERR_LEVEL_ALERT << 12) | 1;


const ERR_LOOKS_OK: i32 = 0;
const ERR_NO_VMA: i32 = (ERR_LEVEL_WARNING << 12) | 1;
const ERR_ANCIENT_THREAD: i32 = (ERR_LEVEL_WARNING << 12) | 2;
const ERR_POSSIBLE_GOLANG_STACK: i32 = (ERR_LEVEL_WARNING << 12) | 3;
const ERR_STACK_PIVOT: i32 = (ERR_LEVEL_ALERT << 12) | 1;


const STACK_SRC_SELF: i32 = 0;
const STACK_SRC_UNK: i32 = -1;
const STACK_SRC_ERR: i32 = -2;

const LOC_UNKNOWN: i32 = 0;
const LOC_clone: i32 = 1;
const LOC_clone3: i32 = 2;
const LOC_execve: i32 = 3;
const LOC_execveat: i32 = 4;
const LOC_fork: i32 = 5;
const LOC_vfork: i32 = 6;
const LOC_socket: i32 = 7;
const LOC_dup2: i32 = 8;
const LOC_dup3: i32 = 9;
const LOC_mmap: i32 = 10;
const LOC_mprotect: i32 = 11;

// when a stack pivot is detected, what kind of action do we take?
const ACTION_UNKNOWN: i32 = 0;
const ACTION_REPORT: i32 = 1;
const ACTION_KILL: i32 = 2;

// counters for stack pivot check statistics
static OK_EVENTS: AtomicU32 = AtomicU32::new(0);
static NO_VMA_EVENTS: AtomicU32 = AtomicU32::new(0);
static ANCIENT_THREAD_EVENTS: AtomicU32 = AtomicU32::new(0);
static STACK_PIVOT_EVENTS: AtomicU32 = AtomicU32::new(0);
static POSSIBLE_GOLANG_STACK_EVENTS: AtomicU32 = AtomicU32::new(0);
static UNKNOWN_EVENTS: AtomicU32 = AtomicU32::new(0);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct ProgramArgs {
    #[arg(short, long)]
    sigkill: bool,
}

fn parse_message<T>(data: &[u8]) -> Option<*const T> {
    if data.len() != mem::size_of::<T>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<T>()
        );
        return None;
    }

    let event = unsafe {
        &*(data.as_ptr() as *const T)
    };

    Some(event)
}

fn stack_pivot_event_handler(data: &[u8]) -> ::std::os::raw::c_int {
    let event = unsafe {
        *parse_message::<stack_pivot_poc_bss_types::stack_pivot_event>(data).unwrap()
    };

    match event.kind {
        ERR_LOOKS_OK => OK_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_NO_VMA => NO_VMA_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_STACK_PIVOT => STACK_PIVOT_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_ANCIENT_THREAD => ANCIENT_THREAD_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_POSSIBLE_GOLANG_STACK => POSSIBLE_GOLANG_STACK_EVENTS.fetch_add(1, Ordering::SeqCst),
        _ => UNKNOWN_EVENTS.fetch_add(1, Ordering::SeqCst),
    };

    let error_label = match event.kind {
        ERR_LOOKS_OK => "Ok",
        ERR_NO_VMA => "No VMA backing stack pointer (???)",
        ERR_STACK_PIVOT => "Stack Pivot",
        ERR_ANCIENT_THREAD => "Ancient Thread (cannot check stack)",
        ERR_POSSIBLE_GOLANG_STACK => "Possbile Golang stack",
        _ => "Unknown Error Value",
    };

    let location_label = match event.location {
        LOC_clone => "clone",
        LOC_clone3 => "clone3",
        LOC_execve => "execve",
        LOC_execveat => "execveat",
        LOC_fork => "fork",
        LOC_vfork => "vfork",
        LOC_socket => "socket",
        LOC_dup2 => "dup2",
        LOC_dup3 => "dup3",
        LOC_mmap => "mmap",
        LOC_mprotect => "mprotect",
        _ => "Unknown",
    };

    let action_label = match event.action {
        ACTION_REPORT => "report",
        ACTION_KILL => "kill",
        _ => "unknown",
    };

    if event.kind == ERR_STACK_PIVOT {
        println!("[stack pivot event]: task: {}:{} event {}, location: {}, sp: {:#x}, vma: [{:#x}, {:#x}), action taken: {}", event.pid, event.tid, error_label, location_label, event.sp, event.stack_start, event.stack_end, action_label);
    }

    0
}

fn main() -> Result<(), Error> {

    let myargs = ProgramArgs::parse();

    println!("[I] sigkill: {}", myargs.sigkill);
    if myargs.sigkill {
    }
    
    let skel_builder = StackPivotPocSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let mut skel = open_skel.load().unwrap();

    // SIGUSR1 handler to print info to stdout
    let mut signals = Signals::new(&[ SIGUSR1 ])?;

    // easy ctrl+c support to cleanly exit & print info
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    let mut maps = skel.maps_mut();
    let sigkill_map = maps.sigkill_enabled();
    let mut key_var = 0_i32;
    let mut val_var = match myargs.sigkill {
        true => 1_i32,
        false => 0_i32,
    };
    let key_bytes = key_var.to_ne_bytes();
    let val_bytes = val_var.to_ne_bytes();

    sigkill_map
        .update(&key_bytes, &val_bytes, MapFlags::ANY)
        .expect("failed to update sigkill setting");


    let mut perf_builder = RingBufferBuilder::new();
    perf_builder.add(skel.maps().ringbuf_map_stack_pivot_event(), move |data| {
        stack_pivot_event_handler(data)
    })
    .unwrap();

    let ringbuf = perf_builder.build().unwrap();

    skel.attach();

    println!("[I] Running! Follow debug output with `sudo less +F /sys/kernel/debug/tracing/trace`");
    println!("[I] stats on received events can be show by sending SIGUSR1 to this process");
    println!("[I] This terminal will only have messages for stack pivot events");

    while running.load(Ordering::SeqCst) {
        ringbuf.poll(Duration::from_millis(100));
        for sig in signals.pending() {
            //match sig as libc::c_int {
            println!("[I] signal: {}", sig);
            match sig {
                SIGUSR1 => {
                    println!("\n[I] statistics for stack pivot checks:");
                    println!("\tOK_EVENTS: {}", OK_EVENTS.load(Ordering::SeqCst));
                    println!("\tNO_VMA_EVENTS: {}", NO_VMA_EVENTS.load(Ordering::SeqCst));
                    println!("\tANCIENT_THREAD_EVENTS: {}", ANCIENT_THREAD_EVENTS.load(Ordering::SeqCst));
                    println!("\tPOSSIBLE_GOLANG_STACK_EVENTS: {}", POSSIBLE_GOLANG_STACK_EVENTS.load(Ordering::SeqCst));
                    println!("\tSTACK_PIVOT_EVENTS: {}", STACK_PIVOT_EVENTS.load(Ordering::SeqCst));
                    println!("\tUNKNOWN_EVENTS: {}", UNKNOWN_EVENTS.load(Ordering::SeqCst));
                },
                _ => unreachable!(),
            }
        }
    }

    println!("\n[I] statistics for stack pivot checks:");
    println!("\tOK_EVENTS: {}", OK_EVENTS.load(Ordering::SeqCst));
    println!("\tNO_VMA_EVENTS: {}", NO_VMA_EVENTS.load(Ordering::SeqCst));
    println!("\tANCIENT_THREAD_EVENTS: {}", ANCIENT_THREAD_EVENTS.load(Ordering::SeqCst));
    println!("\tPOSSIBLE_GOLANG_STACK_EVENTS: {}", POSSIBLE_GOLANG_STACK_EVENTS.load(Ordering::SeqCst));
    println!("\tSTACK_PIVOT_EVENTS: {}", STACK_PIVOT_EVENTS.load(Ordering::SeqCst));
    println!("\tUNKNOWN_EVENTS: {}", UNKNOWN_EVENTS.load(Ordering::SeqCst));

    Ok(())
}
