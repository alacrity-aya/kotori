use crate::config;
use crate::lb::types::backends;
use crate::lb::types::endpoint;
use crate::lb::*;
use core::slice;
use core::time;
use std::fs::File;
use std::mem::MaybeUninit;
use std::net::IpAddr;
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
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

const CGROUP_PATH: &str = "/sys/fs/cgroup";
const MAX_BACKEND_NUMBER: usize = 512;

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

fn wait_signal() -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    print!("ebpf program is running, press 'ctrl + c' to exit");
    while running.load(Ordering::SeqCst) {
        print!(".");
        io::Write::flush(&mut io::stdout())?;
        thread::sleep(time::Duration::from_secs(1));
    }

    println!("\nreceive SIGINT, exit");
    Ok(())
}

fn insert_rules(config: &config::Config, skel: &LbSkel) -> Result<()> {
    for vip in &config.vip {
        let key = match vip.addr {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => bail!("IPv6 not supported yet"),
        };

        let mut endpoints: [endpoint; MAX_BACKEND_NUMBER] =
            [Default::default(); MAX_BACKEND_NUMBER];

        for (i, rip) in vip.rip.iter().enumerate() {
            if let IpAddr::V4(v4) = rip.addr {
                let octets = v4.octets();
                let rip = u32::from_ne_bytes(octets);
                endpoints[i].rip = rip;
            }

            endpoints[i].ports = rip.port;
        }

        let value = backends {
            size: std::cmp::min(vip.rip.len(), MAX_BACKEND_NUMBER) as u32,
            endpoints,
        };

        let value_ptr = &value as *const types::backends as *const u8;
        let value_silce =
            unsafe { slice::from_raw_parts(value_ptr, std::mem::size_of::<types::backends>()) };

        skel.maps.ip_map.update(&key, value_silce, MapFlags::ANY)?;
    }
    Ok(())
}

pub fn load_ebpf_prog(config: &config::Config) -> Result<()> {
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

    insert_rules(config, &skel)?;
    wait_signal()
}
