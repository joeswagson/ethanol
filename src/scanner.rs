
use std::fs;
use std::sync::Mutex;

// Cargo.toml:
// rayon = "1.10"
// libc = "0.2"
use rayon::prelude::*;

pub struct Scanner {
    pub pid: libc::pid_t,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: usize,
    pub end: usize,
    pub executable: bool,  // add this
}


fn hex_pattern_to_bytes(pattern: &str) -> (Vec<u8>, Vec<bool>) {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for token in pattern.split_whitespace() {
        if token.contains('?') {
            bytes.push(0x00);
            mask.push(false);
        } else {
            bytes.push(u8::from_str_radix(token, 16).expect("Invalid hex"));
            mask.push(true);
        }
    }
    (bytes, mask)
}

/// Boyer-Moore-Horspool with wildcard mask support
fn bmh_search(haystack: &[u8], pattern: &[u8], mask: &[bool]) -> Vec<usize> {
    let mut results = Vec::new();
    let pat_len = pattern.len();
    let hay_len = haystack.len();

    if pat_len == 0 || pat_len > hay_len {
        return results;
    }

    // Build bad character shift table (skip wildcards in shift calc)
    let mut skip = [pat_len; 256];
    for i in 0..pat_len.saturating_sub(1) {
        if mask[i] {
            skip[pattern[i] as usize] = pat_len - 1 - i;
        }
    }

    let mut i = pat_len - 1;
    while i < hay_len {
        let mut j = pat_len - 1;
        let mut k = i;
        loop {
            if mask[j] && haystack[k] != pattern[j] {
                // Use last byte shift, but don't skip wildcards
                let shift = if mask[pat_len - 1] {
                    skip[haystack[i] as usize]
                } else {
                    1
                };
                i += shift;
                break;
            }
            if j == 0 {
                results.push(k);
                i += 1;
                break;
            }
            j -= 1;
            k -= 1;
        }
    }

    results
}

/// Read using process_vm_readv — much faster than /proc/mem
fn read_process_memory(pid: libc::pid_t, address: usize, size: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; size];

    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
        iov_len: size,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: size,
    };

    let bytes_read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };

    if bytes_read <= 0 {
        return None;
    }

    buffer.truncate(bytes_read as usize);
    Some(buffer)
}

impl Scanner {
    pub fn new(pid: libc::pid_t) -> Self {
        Scanner { pid }
    }

    fn get_memory_regions(&self) -> Vec<MemoryRegion> {
        let maps_path = format!("/proc/{}/maps", self.pid);
        let content = match fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        content
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(6, ' ');
                let addr_range = parts.next()?;
                let perms = parts.next()?;

                // Only readable regions — mirrors PAGE_EXECUTE_READ / PAGE_READONLY etc.
                if !perms.starts_with('r') {
                    return None;
                }

                let mut addr_parts = addr_range.splitn(2, '-');
                let start = usize::from_str_radix(addr_parts.next()?, 16).ok()?;
                let end = usize::from_str_radix(addr_parts.next()?, 16).ok()?;

                Some(MemoryRegion {
                    start,
                    end,
                    executable: perms.chars().nth(2) == Some('x'),
                })
            })
            .collect()
    }

    pub fn find_pattern(&self, hex_pattern: &str) -> Option<usize> {
        let (pattern_bytes, mask) = hex_pattern_to_bytes(hex_pattern);
        let results = self.scan_internal(&pattern_bytes, &mask, true);
        results.into_iter().next()
    }

    pub fn find_all_patterns(&self, hex_pattern: &str) -> Vec<usize> {
        let (pattern_bytes, mask) = hex_pattern_to_bytes(hex_pattern);
        self.scan_internal(&pattern_bytes, &mask, false)
    }

    fn scan_internal(&self, pattern: &[u8], mask: &[bool], first_only: bool) -> Vec<usize> {
        let regions = self.get_memory_regions();
        let pid = self.pid;
        let found = Mutex::new(Vec::new());

        regions.par_iter().for_each(|region| {
            // Early exit if first_only and already found
            if first_only {
                let f = found.lock().unwrap();
                if !f.is_empty() {
                    return;
                }
            }

            let region_size = region.end - region.start;
            if region_size < pattern.len() {
                return;
            }

            // Read in 32MB chunks to avoid huge single allocations
            const CHUNK_SIZE: usize = 32 * 1024 * 1024;
            // Overlap chunks by pattern.len()-1 to catch cross-boundary matches
            let overlap = pattern.len().saturating_sub(1);
            let mut offset = 0;

            while offset < region_size {
                let chunk_size = CHUNK_SIZE.min(region_size - offset);
                let read_size = if offset + chunk_size < region_size {
                    chunk_size + overlap
                } else {
                    chunk_size
                };
                let read_size = read_size.min(region_size - offset);

                if let Some(buffer) = read_process_memory(pid, region.start + offset, read_size) {
                    let matches = bmh_search(&buffer, pattern, mask);
                    let mut f = found.lock().unwrap();
                    for m in matches {
                        f.push(region.start + offset + m);
                        if first_only {
                            return;
                        }
                    }
                }

                offset += chunk_size;
            }
        });

        let mut results = found.into_inner().unwrap();
        results.sort_unstable();
        results
    }

    pub fn find_ref_to_addr(&self, target_addr: usize) -> Option<usize> {
        let regions = self.get_memory_regions();
        let pid = self.pid;

        for region in regions.iter().filter(|r| r.executable) {
            let region_size = region.end - region.start;
            let buffer = match read_process_memory(pid, region.start, region_size) {
                Some(b) => b,
                None => continue,
            };

            // Walk every byte looking for a RIP-relative reference to target_addr.
            // RIP-relative refs are encoded as a 4-byte signed offset from the
            // end of the instruction. Common prefixes before the offset bytes:
            //   LEA:  48 8D 05 <off32>  (REX.W LEA rax, [rip+off])
            //         48 8D 0D <off32>  etc. (any mod=00 rm=101 encoding)
            //   MOV:  48 8B 05 <off32>
            //   Any instruction with ModRM byte where mod=00, rm=101
            for i in 0..buffer.len().saturating_sub(7) {
                // Look for any 4-byte sequence that, treated as a RIP-relative
                // offset from (region.start + i + <instr_len>), resolves to target_addr.
                // Most RIP-rel instructions are 6-7 bytes; we check offset positions
                // at i+2 (5-byte instr), i+3 (6-byte), i+4 (7-byte).
                for instr_len in [4usize, 5, 6, 7] {
                    let offset_pos = i + instr_len - 4;
                    if offset_pos + 4 > buffer.len() {
                        continue;
                    }

                    let offset =
                        i32::from_le_bytes(buffer[offset_pos..offset_pos + 4].try_into().unwrap());

                    let rip = region.start + i + instr_len;
                    let resolved = (rip as isize + offset as isize) as usize;

                    if resolved == target_addr {
                        let ref_site = region.start + i;
                        println!("Found xref to string at: 0x{:x}", ref_site);

                        // Step 3: Walk backwards to find the function prologue
                        if let Some(func) = self.find_function_start(&buffer, i, region.start) {
                            return Some(func);
                        }
                    }
                }
            }
        }

        None
    }

    /// Walk backwards from `offset` in `buffer` to find a function prologue.
    /// Looks for: 55 (push rbp) or 48 83 EC ?? (sub rsp, N) or 48 89 5C (common prologue)
    fn find_function_start(
        &self,
        buffer: &[u8],
        from_offset: usize,
        region_base: usize,
    ) -> Option<usize> {
        // Max function size we'll scan back through — tune as needed
        const MAX_FUNC_SIZE: usize = 0x10000;

        let scan_start = from_offset.saturating_sub(MAX_FUNC_SIZE);

        // Walk backwards looking for prologue signatures
        let mut i = from_offset;
        while i > scan_start {
            i -= 1;

            // push rbp (55) followed by mov rbp, rsp (48 89 E5)  — classic prologue
            if buffer[i] == 0x55
                && i + 3 < buffer.len()
                && buffer[i + 1] == 0x48
                && buffer[i + 2] == 0x89
                && buffer[i + 3] == 0xE5
            {
                return Some(region_base + i);
            }

            // push rbp alone (55) with a reasonable gap from xref
            // Only accept if preceded by a RET (C3, C2 xx xx) or INT3 (CC) —
            // i.e. end of previous function
            if buffer[i] == 0x55 && i > 0 {
                let prev = buffer[i - 1];
                if prev == 0xC3 || prev == 0xCC || prev == 0xC9 {
                    return Some(region_base + i);
                }
            }

            // sub rsp, N: 48 83 EC ??  or  48 81 EC ?? ?? ?? ??
            if buffer[i] == 0x48
                && i + 3 < buffer.len()
                && buffer[i + 1] == 0x83
                && buffer[i + 2] == 0xEC
            {
                // Likely a prologue — but walk back a bit more to catch any
                // push rbp before it
                let lookahead = i.saturating_sub(4);
                for k in (lookahead..i).rev() {
                    if buffer[k] == 0x55 {
                        return Some(region_base + k);
                    }
                }
                return Some(region_base + i);
            }
        }

        println!("Could not find clean prologue, returning closest candidate.");
        None
    }

    pub fn dump_pattern_at(&self, addr: usize, len: usize) {
        if let Some(buf) = read_process_memory(self.pid, addr, len) {
            let hex: Vec<String> = buf.iter().map(|b| format!("{:02X}", b)).collect();
            println!("Pattern: {}", hex.join(" "));
        }
    }
}
