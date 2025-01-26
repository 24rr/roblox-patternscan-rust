use std::time::Instant;
use std::thread;
use std::time::Duration;
use colored::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Diagnostics::Debug::*;
use serde_json::Value;
use std::fs;

struct ProcessInfo {
    pid: u32,
    base_address: usize,
}

fn find_roblox_clients() -> Option<ProcessInfo> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let snapshot_handle = HANDLE(snapshot.0);
        
        
        struct SnapshotGuard(HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                unsafe { let _ = CloseHandle(self.0); }
            }
        }
        let _guard = SnapshotGuard(snapshot_handle);

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if Process32FirstW(snapshot, &mut entry).is_err() {
            return None;
        }

        while Process32NextW(snapshot, &mut entry).is_ok() {
            let process_name = String::from_utf16_lossy(&entry.szExeFile)
                .trim_matches('\0')
                .to_lowercase();
            
            if process_name == "robloxplayerbeta.exe" {
                let pid = entry.th32ProcessID;
                let process_handle = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    pid,
                ).ok()?;

                
                struct ProcessGuard(HANDLE);
                impl Drop for ProcessGuard {
                    fn drop(&mut self) {
                        unsafe { let _ = CloseHandle(self.0); }
                    }
                }
                let _guard = ProcessGuard(process_handle);
                
                let mut module_handles = [HMODULE::default(); 1024];
                let mut bytes_needed = 0;
                
                if K32EnumProcessModules(
                    process_handle,
                    module_handles.as_mut_ptr(),
                    std::mem::size_of_val(&module_handles) as u32,
                    &mut bytes_needed,
                ).as_bool() {
                    let base_address = module_handles[0].0 as usize;
                    return Some(ProcessInfo { pid, base_address });
                }
            }
        }
        None
    }
}

fn find_pattern(process_handle: HANDLE, base_address: usize, pattern: &str) -> Option<usize> {
    
    let pattern_bytes: Vec<Option<u8>> = pattern
        .split_whitespace()
        .map(|byte_str| {
            if byte_str.contains('?') {
                None
            } else {
                Some(u8::from_str_radix(byte_str, 16).ok()?)
            }
        })
        .collect();

    if pattern_bytes.is_empty() {
        return None;
    }

    unsafe {
        
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        let mut address = base_address;
        
        
        const CHUNK_SIZE: usize = 4 * 1024 * 1024; 
        let mut buffer = vec![0u8; CHUNK_SIZE];

        while VirtualQueryEx(
            process_handle,
            Some(address as *const _),
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0 {
            
            if mem_info.State == MEM_COMMIT
            // mem info is not protected by a guard or no access
                && (mem_info.Protect & PAGE_PROTECTION_FLAGS(PAGE_GUARD.0)) == PAGE_PROTECTION_FLAGS(0)
                && (mem_info.Protect & PAGE_PROTECTION_FLAGS(PAGE_NOACCESS.0)) == PAGE_PROTECTION_FLAGS(0) {
                
                let region_size = mem_info.RegionSize;
                let mut offset = 0;

                while offset < region_size {
                    let bytes_to_read = CHUNK_SIZE.min(region_size - offset);
                    let current_address = address + offset;
                    let mut bytes_read = 0;

                    if ReadProcessMemory(
                        process_handle,
                        current_address as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        bytes_to_read,
                        Some(&mut bytes_read), // read the bytes into the buffer
                    ).is_ok() && bytes_read > 0 {
                        
                        'outer: for i in 0..bytes_read {
                            for (j, &pattern_byte) in pattern_bytes.iter().enumerate() {
                                if i + j >= bytes_read {
                                    continue 'outer;
                                }
                                if let Some(byte) = pattern_byte {
                                    if buffer[i + j] != byte {
                                        continue 'outer;
                                    }
                                }
                            }
                            return Some(current_address + i);
                        }
                    }
                    offset += bytes_to_read;
                }
            }
            address += mem_info.RegionSize;
        }
        None
    }
}

fn main() {
    control::set_virtual_terminal(true).unwrap_or_default();
    println!("{}", "=========================================".bold());
    println!("{}", "Roblox Pattern Scanner\nBy: bufferization".bold());
    println!("{}", "=========================================".bold());
    println!("\n{}", "[Finding Roblox Process & Module Address]\n=========================================".bold());

    let process_info = match find_roblox_clients() {
        Some(info) => info,
        None => {
            println!("[-] {}", "Couldn't find any Roblox Clients to inject into!".red());
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            return;
        }
    };

    println!("[+] RobloxPlayerBeta PID: {}", process_info.pid.to_string().bright_cyan());
    println!("[+] RobloxPlayerBeta Module Address: {:#x}\n", process_info.base_address);

    println!("{}", "[Finding Pattern & Offsets]\n===========================".bold());

    let start_time = Instant::now();
    let process_handle = match unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process_info.pid,
        )
    } {
        Ok(handle) => handle,
        Err(e) => {
            println!("[-] {}: {:?}", "Failed to open process".red(), e);
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            return;
        }
    };

    let patterns_json = match fs::read_to_string("patterns.json") {
        Ok(content) => content,
        Err(e) => {
            println!("[-] {}: {:?}", "Failed to read patterns.json".red(), e);
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            return;
        }
    };

    let patterns_data: Value = match serde_json::from_str(&patterns_json) {
        Ok(data) => data,
        Err(e) => {
            println!("[-] {}: {:?}", "Failed to parse patterns.json".red(), e);
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            return;
        }
    };

    let patterns_array = match patterns_data["patterns"].as_array() {
        Some(arr) => arr,
        None => {
            println!("[-] {}", "Invalid patterns.json format".red());
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            return;
        }
    };

    let mut found_patterns = vec![false; patterns_array.len()];
    let mut attempts = 0;
    const MAX_ATTEMPTS: i32 = 30;

    while !found_patterns.iter().all(|&x| x) && attempts < MAX_ATTEMPTS {
        for (i, pattern_obj) in patterns_array.iter().enumerate() {
            if !found_patterns[i] {
                let name = pattern_obj["name"].as_str().unwrap_or("Unknown");
                let pattern = pattern_obj["pattern"].as_str().unwrap_or(""); // pattern to search for
                
                if let Some(address) = find_pattern(process_handle, process_info.base_address, pattern) {
                    println!("[+] {} found at address: {:#x}", name.bright_green(), address);
                    found_patterns[i] = true;
                }
            }
        }
        attempts += 1;
        thread::sleep(Duration::from_secs(1));
    }

    let elapsed = start_time.elapsed();
    
    if !found_patterns.iter().all(|&x| x) {
        println!("\n[-] {}", format!("Could not find all patterns after {} seconds", elapsed.as_secs_f64()).red());
        
        for (i, pattern_obj) in patterns_array.iter().enumerate() {
            if !found_patterns[i] {
                let name = pattern_obj["name"].as_str().unwrap_or("Unknown");
                println!("[-] {}: {}", "Pattern not found".red(), name.yellow());
            }
        }
    } else {
        println!("\n[+] {}", format!("All patterns found in {} seconds", elapsed.as_secs_f64()).bright_green());
    }

    unsafe {
        let _ = CloseHandle(process_handle);
    }
    
    println!("\nPress Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap_or_default();
}