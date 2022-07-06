use std::io::Error;
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

extern crate libbpf_rs;
use libbpf_rs::RingBufferBuilder;

#[path = "bpf/.output/stack_pivot_poc.skel.rs"]
mod stack_pivot_poc;
use stack_pivot_poc::*;

// ok: return 0
// error: return 1
fn clone_data_event_handler(data: &[u8]) -> ::std::os::raw::c_int {
    // todo process/print data
    if data.len() != mem::size_of::<stack_pivot_poc_bss_types::clone_data>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<stack_pivot_poc_bss_types::clone_data>()
        );
        return 1;
    }

    let event = unsafe {
        &*(data.as_ptr() as *const stack_pivot_poc_bss_types::clone_data)
    };

    println!("[clone event] tgid:pid {}:{}", event.data.pid, event.data.tid);

    0
}

// ok: return 0
// error: return 1
fn clone_data_ret_event_handler(data: &[u8]) -> ::std::os::raw::c_int {
    // todo process/print data
    if data.len() != mem::size_of::<stack_pivot_poc_bss_types::clone_data>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<stack_pivot_poc_bss_types::clone_data>()
        );
        return 1;
    }

    let event = unsafe {
        &*(data.as_ptr() as *const stack_pivot_poc_bss_types::clone_data)
    };

    println!("[clone return] tgid:pid {}:{}", event.data.pid, event.data.tid);

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
    perf_builder.add(skel.maps().ringbuf_map_clone(), move |data| {
        clone_data_event_handler(data)
    })
    .unwrap();
    perf_builder.add(skel.maps().ringbuf_map_clone_ret(), move |data| {
        clone_data_ret_event_handler(data)
    })
    .unwrap();
    let ringbuf = perf_builder.build().unwrap();

    skel.attach();

    while running.load(Ordering::SeqCst) {
        ringbuf.poll(Duration::from_millis(100));
    }

    Ok(())
}
