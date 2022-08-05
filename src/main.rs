use std::io::Error;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

extern crate libbpf_rs;
use libbpf_rs::RingBufferBuilder;

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

// counters for stack pivot check statistics
static OK_EVENTS: AtomicU32 = AtomicU32::new(0);
static NO_VMA_EVENTS: AtomicU32 = AtomicU32::new(0);
static ANCIENT_THREAD_EVENTS: AtomicU32 = AtomicU32::new(0);
static STACK_PIVOT_EVENTS: AtomicU32 = AtomicU32::new(0);
static POSSIBLE_GOLANG_STACK_EVENTS: AtomicU32 = AtomicU32::new(0);
static UNKNOWN_EVENTS: AtomicU32 = AtomicU32::new(0);

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
        *parse_message::<stack_pivot_poc_bss_types::stack_pivot_event_t>(data).unwrap()
    };

    match event.data.err {
        ERR_LOOKS_OK => OK_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_NO_VMA => NO_VMA_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_STACK_PIVOT => STACK_PIVOT_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_ANCIENT_THREAD => ANCIENT_THREAD_EVENTS.fetch_add(1, Ordering::SeqCst),
        ERR_POSSIBLE_GOLANG_STACK => POSSIBLE_GOLANG_STACK_EVENTS.fetch_add(1, Ordering::SeqCst),
        _ => UNKNOWN_EVENTS.fetch_add(1, Ordering::SeqCst),
    };

    let error_label = match event.data.err {
        ERR_LOOKS_OK => "Ok",
        ERR_NO_VMA => "No VMA backing stack pointer (???)",
        ERR_STACK_PIVOT => "Stack Pivot",
        ERR_ANCIENT_THREAD => "Ancient Thread (cannot check stack)",
        ERR_POSSIBLE_GOLANG_STACK => "Possbile Golang stack",
        _ => "Unknown Error Value",
    };

    let source_label = match event.data.stack_src {
        STACK_SRC_SELF => "Self",
        STACK_SRC_UNK => "Unknown",
        STACK_SRC_ERR => "Error",
        _ => "Unknown Source Value",
    };

    if event.data.err == ERR_STACK_PIVOT {
        println!("[stack pivot event]: task: {}:{} event {}, sp: {:#x}, source {} vma: [{:#x}, {:#x})", event.data.pid, event.data.tid, error_label, event.data.sp, source_label, event.data.stack_start, event.data.stack_end);
    }

    0
}

fn main() -> Result<(), Error> {
    
    let skel_builder = StackPivotPocSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let mut skel = open_skel.load().unwrap();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    let mut perf_builder = RingBufferBuilder::new();
    perf_builder.add(skel.maps().ringbuf_map_stack_pivot_event(), move |data| {
        stack_pivot_event_handler(data)
    })
    .unwrap();

    let ringbuf = perf_builder.build().unwrap();

    skel.attach();

    println!("[I] Running! Follow debug output with `sudo less +F /sys/kernel/debug/tracing/trace`");
    println!("[I] This terminal will only have messages for stack pivot events");

    while running.load(Ordering::SeqCst) {
        ringbuf.poll(Duration::from_millis(100));
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
