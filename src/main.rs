const NAME: &str = "sober";
const ERR_ACCESS: &str = "Access to process denied.";

use std::fs;
use std::ops::Index;
use sysinfo::{Pid, Process, System};

fn get_modules(pid: u32) -> Vec<String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = match fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut modules: Vec<String> = content
        .lines()
        .filter_map(|line| {
            let path = line.split_whitespace().last()?;
            if path.starts_with('/') {
                Some(path.to_string())
            } else {
                None
            }
        })
        .collect();

    modules.sort();
    modules.dedup();
    modules
}
use std::env;
fn main() {
    let args: Vec<String> = env::args().collect();
    let mut sys = System::new_all();
    sys.refresh_all();

    println!("Searching for processes");

    const PROC_TAKE: usize = 16;

    let mut pos:usize = 0;
    let mut found:usize = 0;
    let mut parent_buf = [0; PROC_TAKE];
    let proc: Option<Process>;

    for (pid, proc) in sys.processes() {
        if found >= PROC_TAKE {
            break;
        }

        let pname;
        match proc.exe() {
            None => continue,
            Some(path) => pname = path.to_str().unwrap_or(ERR_ACCESS),
        }

        if !pname.ends_with(NAME) {
            continue;
        }

        match proc.parent() {
            None => {}
            Some(parent_pid) => {
                found += 1;
                parent_buf[pos] = parent_pid.as_u32();
                println!("Sober process {} forked from {}", pid, parent_pid);
            }
        }

        // println!("Process {}: {:?} {:?}", pid, pname, proc.parent());
        // let mem = proc .memory();
        // println!("- RAM (B): {}", mem);

        pos += 1;
    }

    print!("Finding parent with most forks.");

    // process buffer
    let mut occ_buf = [0; 16];
    for i in 0..occ_buf.len() - 1 {
        let parent_pid = parent_buf[i];
        match parent_buf.iter().position(|&x| x == parent_pid) {
            Some(parent_idx) => occ_buf[parent_idx] += 1,
            None => {}
        }
    }

    let (parent_idx, _) = match occ_buf.iter().enumerate().max_by_key(|&(_, v)| v) {
        None => {
            println!("A game process could not be found.");
            return;
        }
        Some(pair) => pair,
    };

    let sober_pid = parent_buf[parent_idx];
    println!("Sober parent PID: {}", sober_pid);

    print!("Performing memory sanity check...");
    let proc;
    match sys.processes().iter().find(|(pid, _)| pid.as_u32() == sober_pid){
        None => {
            print!("Could not find PID from process list.");
            return;
        }
        Some((_, original_proc)) => {
            proc = original_proc;
        }
    }

    const U_BYTES:u64 = 1024^2; // where U = MiB
    const MIN_MEM:u64 = 250; // in whatever units specified above

    // let check_mem = args.contains("--no-memory-check");
    let mem = proc.memory();
    println!("Process memory in bytes: {}", mem);
    if(mem < MIN_MEM * U_BYTES){
        println!("Process uses a suspiciously low amount of memory, probably made incorrect assumption. Run with the '--no-memory-check' flag to disable this if you have verified the process.");
        return;
    }

    println!("Process passed memory check!");
}
