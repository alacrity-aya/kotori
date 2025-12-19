use crate::lb::*;
use core::time;
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::{io, thread};

use anyhow::Ok;
use anyhow::Result;
use anyhow::bail;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

const CGROUP_PATH: &str = "/sys/fs/cgroup";

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn load_ebpf_prog() -> Result<()> {
    bump_memlock_rlimit()?;

    let skel_builder = LbSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut skel = skel_builder.open(&mut open_object)?.load()?;

    let cgroup_file = File::open(CGROUP_PATH)?;
    let cgroup_fd = cgroup_file.as_fd();

    let link = skel
        .progs
        .load_balance
        .attach_cgroup(cgroup_fd.as_raw_fd())?;

    skel.links = LbLinks {
        load_balance: Some(link),
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    print!("ebpf program is running");
    while running.load(Ordering::SeqCst) {
        print!(".");
        io::Write::flush(&mut io::stdout())?;
        thread::sleep(time::Duration::from_secs(1));
    }

    println!("\nreceive SIGINT, exit");

    Ok(())
}
