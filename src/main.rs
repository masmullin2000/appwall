use anyhow::{bail, Result};
use libbpf_rs::{RingBufferBuilder, MapFlags, TcHookBuilder, EGRESS, INGRESS};
use procfs::process::*;
use structopt::StructOpt;
use plain::{from_bytes, Plain};

#[path = "bpf/.output/appwall.skel.rs"]
mod tc;
use tc::appwall_bss_types::allowed_file;
use tc::*;

unsafe impl Plain for appwall_bss_types::error_pid_data_t {}

fn str_from_u8_nul(src: &[u8]) -> &str {
    let end = src.iter().position(|&c| c == 0).unwrap_or(src.len());

    std::str::from_utf8(&src[0..end]).unwrap_or("Unknown")
}

#[derive(Debug, StructOpt)]
struct Command {
    /// attach a hook
    #[structopt(short = "a", long = "attach")]
    attach: bool,

    /// destroy all hooks on clsact
    #[structopt(short = "d", long = "destroy", conflicts_with = "attach")]
    destroy: bool,

    /// interface to attach to
    #[structopt(short = "i", long = "interface")]
    iface: String,

    /// allowed binaries config file
    #[structopt(short = "c", long = "config", default_value = "")]
    config_file: String,
}

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

fn get_allowed_bins(allow_cfg: &str) -> Result<([allowed_file; 1024], Vec<i32>)> {
    let mut file = [allowed_file::default(); 1024];
    let mut pids: Vec<i32> = Vec::new();

    let file_data = std::fs::read_to_string(allow_cfg)?;

    let data: Vec<String> = file_data
        .lines()
        .filter_map(|x| {
            let mut y = String::from(x);
            y.retain(|c| !c.is_whitespace() && c.is_ascii());
            if y.is_empty() {
                None
            } else {
                Some(y)
            }
        })
        .collect();

    if data.is_empty() {
        bail!("Empty Config file");
    }

    for (i, line) in data.iter().enumerate() {
        if let Ok(fstat) = nix::sys::stat::lstat(line.as_str()) {
            file[i].ino = fstat.st_ino;
            file[i].dev = fstat.st_dev as u32;
        }
    }

    all_processes()?
        .iter()
        .filter(|x| x.exe().is_ok())
        .map(|x| (x.pid(), x.exe().unwrap().to_string_lossy().to_string()))
        .for_each(|(x, y)| {
            if data.iter().any(|d| d == &y) {
                pids.push(x);
            }
        });

    Ok((file, pids))
}

fn as_byte_stream<T: Sized>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((val as *const T) as *const u8, std::mem::size_of::<T>()) }
}

fn populate_maps(
    files: &[allowed_file; 1024],
    pids: &[i32],
    skel: &mut AppwallSkel,
) -> Result<()> {
    for (i, f) in files.iter().enumerate() {
        let key = (i as u32).to_ne_bytes();
        let val = as_byte_stream(f);
        skel.maps_mut()
            .allowed_bins()
            .update(&key, val, MapFlags::ANY)?;
    }

    for pid in pids {
        let key = pid.to_ne_bytes();
        let val = 1_i8.to_ne_bytes();
        skel.maps_mut()
            .allowed_pids()
            .update(&key, &val, MapFlags::ANY)?;
    }

    Ok(())
}

fn ready_prog(prog_name: &str, skel: &mut AppwallSkel, attach: bool) -> Result<()> {
    if let Some(prog) = skel.obj.prog_mut(prog_name) {
        let path = format!("/sys/fs/bpf/appwall_{}", prog_name);
        let _ = prog.unpin(&path);

        if attach {
            let mut p = prog.attach()?;
            p.pin(path)?;
        }
        Ok(())
    } else {
        bail!("error")
    }
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    bump_memlock_rlimit()?;

    let builder = AppwallSkelBuilder::default();
    let open = builder.open()?;
    let mut skel = open.load()?;
    let fd = skel.progs().handle_egress().fd();
    let ifidx = nix::net::if_::if_nametoindex(opts.iface.as_str())? as i32;

    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(fd)
        .ifindex(ifidx)
        .replace(true)
        .handle(1)
        .priority(1);

    let val = 0_u64;
    for i in 0..65535_u16 {
        let key = i.to_ne_bytes();
        let val = val.to_ne_bytes();
        skel.maps_mut()
            .allowed_egress_ports()
            .update(&key, &val, MapFlags::ANY)?;
    }

    ready_prog("handle_exec", &mut skel, opts.attach)?;
    ready_prog("handle_exit", &mut skel, opts.attach)?;
    ready_prog("handle_socks", &mut skel, opts.attach)?;

    if opts.attach {
        match get_allowed_bins(&opts.config_file) {
            Ok((files, pids)) => populate_maps(&files, &pids, &mut skel)?,
            Err(e) => {
                println!("{}", e);
            }
        }

        let mut egress = tc_builder.hook(EGRESS);
        egress.create()?;
        egress.attach()?;

        let handle_errors = move |data: &[u8]| -> i32 {
            if let Ok(info) = from_bytes::<appwall_bss_types::error_pid_data_t>(data) {
                println!("error pid {} comm {}", info.tgid, str_from_u8_nul(&info.comm));
            }
            0
        };

        let mut rbbuild = RingBufferBuilder::new();
        rbbuild.add(skel.maps().error_pids(), handle_errors)?;
        let rb = rbbuild.build()?;

        loop {
            rb.poll(std::time::Duration::from_secs(1))?;
        };
    } else if opts.destroy {
        let mut destroyer = tc_builder.hook(EGRESS | INGRESS);
        destroyer.destroy()?;
    }

    Ok(())
}
