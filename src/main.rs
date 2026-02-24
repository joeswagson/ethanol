mod scanner;

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
use std::ptr::null;
use crate::scanner::Scanner;

fn find_sober(args: Vec<String>) -> Option<u32> {
    let sys = System::new_all();
    println!("Searching for processes");

    const PROC_TAKE: usize = 16;

    let mut pos: usize = 0;
    let mut found: usize = 0;
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

    println!("Finding parent with most forks.");

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
            return None;
        }
        Some(pair) => pair,
    };

    let sober_pid = parent_buf[parent_idx];
    println!("Sober parent PID: {}", sober_pid);

    println!("Performing memory sanity check...");
    let sober_proc;
    match sys.processes().iter().find(|(pid, _)| pid.as_u32() == sober_pid) {
        None => {
            println!("Could not find PID from process list.");
            return None;
        }
        Some((_, original_proc)) => {
            sober_proc = original_proc;
        }
    }

    const U_BYTES: u64 = 1024 ^ 2; // where U = MiB
    const MIN_MEM: u64 = 250; // in whatever units specified above

    // let check_mem = args.contains("--no-memory-check");
    let mem = sober_proc.memory();
    println!("Process memory in bytes: {}", mem);
    if (mem < MIN_MEM * U_BYTES) {
        println!("Process uses a suspiciously low amount of memory, probably made incorrect assumption. Run with the '--no-memory-check' flag to disable this if you have verified the process.");
        return None;
    }

    println!("Process passed memory check!");

    println!("Checking modules for apk.");
    if get_modules(sober_pid).iter().all(|module| !module.ends_with("com.roblox.client/base.apk")) {
        println!("Process didn't have the roblox apk loaded.");
        return None;
    }

    Some(sober_pid)
}

// In main.rs — add this after finding func_addr
use std::ffi::CString;

pub fn inject_and_call(pid: libc::pid_t, func_addr: usize) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // 1. Attach to process
        if libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) < 0 {
            return Err("ptrace attach failed".into());
        }

        // Wait for process to stop
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);

        // 2. Save original registers
        let mut regs: libc::user_regs_struct = std::mem::zeroed();
        libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs);
        let saved_regs = regs;

        // 3. Find a RWX region or mmap one in the target
        //    Easier: write shellcode into an existing executable region temporarily
        //    We'll use the stack approach — write shellcode near rsp
        let shellcode_addr = regs.rsp as usize - 0x1000; // below current stack

        // Shellcode: call func_addr with desired args, then int3 so we regain control
        // mov rdi, <arg>       ; 48 BF <8 bytes>
        // mov rax, <func_addr> ; 48 B8 <8 bytes>
        // call rax             ; FF D0
        // int3                 ; CC
        let arg: u64 = 8; // identity level
        let mut shellcode = Vec::new();
        shellcode.extend_from_slice(&[0x48, 0xBF]);
        shellcode.extend_from_slice(&arg.to_le_bytes());
        shellcode.extend_from_slice(&[0x48, 0xB8]);
        shellcode.extend_from_slice(&(func_addr as u64).to_le_bytes());
        shellcode.extend_from_slice(&[0xFF, 0xD0]); // call rax
        shellcode.extend_from_slice(&[0xCC]);        // int3 — signals us when done

        // 4. Write shellcode into target process memory
        write_to_process(pid, shellcode_addr, &shellcode)?;

        // 5. Redirect RIP to shellcode
        regs.rip = shellcode_addr as u64;
        libc::ptrace(libc::PTRACE_SETREGS, pid, 0, &regs);

        // 6. Continue until int3 hit
        libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
        libc::waitpid(pid, &mut status, 0); // waits for SIGTRAP from int3

        // 7. Restore original registers and detach
        libc::ptrace(libc::PTRACE_SETREGS, pid, 0, &saved_regs);
        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
    }

    Ok(())
}

/// Write bytes into target process via /proc/pid/mem
fn write_to_process(pid: libc::pid_t, addr: usize, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Seek, SeekFrom, Write};

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&mem_path)?;

    file.seek(SeekFrom::Start(addr as u64))?;
    file.write_all(data)?;

    Ok(())
}
fn main() {
    let args: Vec<String> = env::args().collect();

    let sys = System::new_all();
    let (sober_pid, sober_proc);
    match find_sober(args) {
        None => {
            println!("Failed to find sober process.");
            return;
        }

        Some(pid) => {
            sober_pid = pid;

            match sys.process(Pid::from_u32(pid)) {
                None => {
                    println!("Sober was closed.");
                    return;
                }
                Some(proc) => { sober_proc = proc; }
            };
        }
    }

    println!("Got process {:?} with id {}", sober_proc.name(), sober_pid);
    // for module in get_modules(sober_pid) {
    //     println!("{}", module);
    // }

    let scanner = Scanner::new(libc::pid_t::from(sober_pid.cast_signed()));
    let string_addr = match
    scanner.find_pattern("55 48 89 E5 41 57 41 56 53 50 49 89 FF 48 8D 3D 70 A6 60 03 E8 53 69 8D FE 48 8D 0D F7 A6 FC FF")//"43 75 72 72 65 6E 74 20 69 64 65 6E 74 69 74 79 20 69 73")
    {
        Some(addr) => {
            println!("Found print address! {}", addr);
            addr
        }
        None => {
            eprintln!("Failed to find print address in memory.");
            return;
        }
    };

        println!("PrintIdentity at: 0x{:x}", string_addr);
        match inject_and_call(libc::pid_t::from(sober_pid.cast_signed()), string_addr) {
            Ok(_) => println!("Called successfully!"),
            Err(e) => eprintln!("Call failed: {}", e),
        }

    return;

    let func_addr = scanner.find_ref_to_addr(string_addr);
    match func_addr {
        Some(addr) => println!("PrintIdentity subroutine at: 0x{:x}", addr),
        None => eprintln!("Could not find subroutine."),
    }

    if let Some(func_addr) = func_addr {
        println!("PrintIdentity at: 0x{:x}", func_addr);
        scanner.dump_pattern_at(func_addr, 32);
    }
}
