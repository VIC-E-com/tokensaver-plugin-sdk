use super::LinuxKernelError;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;
const BPF_RET: u16 = 0x06;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const CLONE_THREAD: u32 = 0x0001_0000;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(target_arch = "x86")]
const AUDIT_ARCH: u32 = 0x4000_0003;
#[cfg(target_arch = "arm")]
const AUDIT_ARCH: u32 = 0x4000_0028;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "x86",
    target_arch = "arm"
)))]
compile_error!("Linux certification confinement needs an audited seccomp architecture");

const DENIED: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_ptrace,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_setns,
    libc::SYS_unshare,
    libc::SYS_reboot,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_execveat,
];

#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "arm"))]
const LEGACY_PROCESS_CREATION: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const LEGACY_PROCESS_CREATION: &[libc::c_long] = &[];

const FILTER_LENGTH: usize = 4 + (DENIED.len() + LEGACY_PROCESS_CREATION.len()) * 2 + 8;
static FILTER: [libc::sock_filter; FILTER_LENGTH] = build_filter();

pub(super) fn apply() -> Result<(), LinuxKernelError> {
    let program = libc::sock_fprog {
        len: FILTER_LENGTH as u16,
        filter: FILTER.as_ptr().cast_mut(),
    };
    // SAFETY: no_new_privs permanently prevents privilege gain before filter installation.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(LinuxKernelError);
    }
    // SAFETY: program references the static architecture-checked filter for the complete call.
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0u32,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        return Err(LinuxKernelError);
    }
    Ok(())
}

const fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: yes,
        jf: no,
        k: value,
    }
}

const fn build_filter() -> [libc::sock_filter; FILTER_LENGTH] {
    let zero = statement(0, 0);
    let mut filter = [zero; FILTER_LENGTH];
    let mut index = 0;
    filter[index] = statement(BPF_LD | BPF_W | BPF_ABS, 4);
    index += 1;
    filter[index] = jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0);
    index += 1;
    filter[index] = statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    index += 1;
    filter[index] = statement(BPF_LD | BPF_W | BPF_ABS, 0);
    index += 1;
    let mut denied = 0;
    while denied < DENIED.len() {
        filter[index] = jump(BPF_JMP | BPF_JEQ | BPF_K, DENIED[denied] as u32, 0, 1);
        index += 1;
        filter[index] = statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32);
        index += 1;
        denied += 1;
    }
    let mut legacy = 0;
    while legacy < LEGACY_PROCESS_CREATION.len() {
        filter[index] = jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            LEGACY_PROCESS_CREATION[legacy] as u32,
            0,
            1,
        );
        index += 1;
        filter[index] = statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32);
        index += 1;
        legacy += 1;
    }
    filter[index] = jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_clone3 as u32, 0, 1);
    index += 1;
    filter[index] = statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32);
    index += 1;
    filter[index] = jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_clone as u32, 0, 4);
    index += 1;
    filter[index] = statement(BPF_LD | BPF_W | BPF_ABS, 16);
    index += 1;
    filter[index] = statement(BPF_ALU | BPF_AND | BPF_K, CLONE_THREAD);
    index += 1;
    filter[index] = jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1);
    index += 1;
    filter[index] = statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32);
    index += 1;
    filter[index] = statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_is_complete_and_ends_in_allow() {
        assert_eq!(FILTER.len(), FILTER_LENGTH);
        assert_eq!(FILTER[0].k, 4);
        assert_eq!(FILTER[1].k, AUDIT_ARCH);
        assert_eq!(FILTER[FILTER.len() - 1].k, SECCOMP_RET_ALLOW);
        for syscall in DENIED {
            assert!(
                FILTER
                    .iter()
                    .any(|instruction| instruction.k == *syscall as u32)
            );
        }
        for syscall in LEGACY_PROCESS_CREATION {
            assert!(
                FILTER
                    .iter()
                    .any(|instruction| instruction.k == *syscall as u32)
            );
        }
    }

    #[test]
    fn filter_decisions_deny_network_processes_and_wrong_arch_but_allow_threads() {
        assert_eq!(evaluate(AUDIT_ARCH, libc::SYS_read, 0), SECCOMP_RET_ALLOW);
        assert_eq!(
            evaluate(AUDIT_ARCH, libc::SYS_socket, 0),
            SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            evaluate(AUDIT_ARCH, libc::SYS_clone3, 0),
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
        assert_eq!(
            evaluate(AUDIT_ARCH, libc::SYS_clone, 0),
            SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            evaluate(AUDIT_ARCH, libc::SYS_clone, CLONE_THREAD as u64),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(AUDIT_ARCH ^ 1, libc::SYS_read, 0),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    fn evaluate(arch: u32, syscall: libc::c_long, argument_zero: u64) -> u32 {
        let mut accumulator = 0u32;
        let mut pc = 0usize;
        loop {
            let instruction = FILTER[pc];
            match instruction.code {
                code if code == (BPF_LD | BPF_W | BPF_ABS) => {
                    accumulator = match instruction.k {
                        0 => syscall as u32,
                        4 => arch,
                        16 => argument_zero as u32,
                        _ => panic!("unexpected seccomp offset"),
                    };
                    pc += 1;
                }
                code if code == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    pc += 1 + if accumulator == instruction.k {
                        instruction.jt as usize
                    } else {
                        instruction.jf as usize
                    };
                }
                code if code == (BPF_ALU | BPF_AND | BPF_K) => {
                    accumulator &= instruction.k;
                    pc += 1;
                }
                code if code == (BPF_RET | BPF_K) => return instruction.k,
                _ => panic!("unexpected seccomp instruction"),
            }
        }
    }
}
