// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet
//
// linux-elf-suspicious.yar — small starter ruleset for the v26.5.2
// YARA scanner module. The rules look for *signals*, not signatures —
// concrete malware families belong in operator-supplied rule packs
// (livehunt feeds, ClamAV-Yara, abuse.ch). Each rule is intentionally
// conservative: a single hit is interesting, multiple hits across one
// binary is "look at this now".
//
// Tested locally against:
//   - clean /bin/ls, /bin/cat, /usr/bin/curl on Debian and Alpine: no match
//   - reverse-shell PoC built from public examples: hits reverse_shell_*
//   - common Linux ELF dropper shapes: hits process_injection_*

rule linux_elf_reverse_shell_strings
{
    meta:
        author      = "usulnet"
        description = "ELF binary embedding strings characteristic of an interactive reverse shell"
        severity    = "high"
        family      = "reverse_shell"
        reference   = "https://attack.mitre.org/techniques/T1059/004/"

    strings:
        $bash_rev_1 = "bash -i >& /dev/tcp/" ascii
        $bash_rev_2 = "0<&196;exec 196<>/dev/tcp/" ascii
        $bash_rev_3 = "/dev/tcp/" ascii
        $bash_rev_4 = "/dev/udp/" ascii
        $py_pty     = "pty.spawn(\"/bin/" ascii
        $py_socket  = "socket.SOCK_STREAM" ascii
        $nc_e       = "nc -e /bin/" ascii
        $magic_elf  = { 7F 45 4C 46 }

    condition:
        $magic_elf at 0 and 2 of ($bash_rev_*, $py_pty, $py_socket, $nc_e)
}

rule linux_elf_process_injection_ptrace
{
    meta:
        author      = "usulnet"
        description = "ELF binary linking ptrace + remote-thread style strings (manual process injection)"
        severity    = "medium"
        family      = "process_injection"
        reference   = "https://attack.mitre.org/techniques/T1055/"

    strings:
        $ptrace        = "ptrace" ascii
        $ptrace_attach = "PTRACE_ATTACH" ascii
        $ptrace_poke   = "PTRACE_POKETEXT" ascii
        $ptrace_pokeu  = "PTRACE_POKEUSER" ascii
        $ptrace_setreg = "PTRACE_SETREGS" ascii
        $magic_elf     = { 7F 45 4C 46 }

    condition:
        $magic_elf at 0 and $ptrace and 2 of ($ptrace_attach, $ptrace_poke, $ptrace_pokeu, $ptrace_setreg)
}

rule linux_elf_persistence_systemd_cron
{
    meta:
        author      = "usulnet"
        description = "ELF binary embedding paths that match systemd unit / cron persistence drops"
        severity    = "medium"
        family      = "persistence"
        reference   = "https://attack.mitre.org/techniques/T1543/002/"

    strings:
        $svc_user   = "/etc/systemd/system/" ascii
        $svc_lib    = "/usr/lib/systemd/system/" ascii
        $cron_root  = "/etc/cron.d/" ascii
        $cron_hr    = "/etc/cron.hourly/" ascii
        $crontab_u  = "/var/spool/cron/crontabs/" ascii
        $bashrc     = "/etc/bash.bashrc" ascii
        $profile_d  = "/etc/profile.d/" ascii
        $magic_elf  = { 7F 45 4C 46 }

    condition:
        $magic_elf at 0 and 2 of ($svc_*, $cron_*, $crontab_u, $bashrc, $profile_d)
}

rule linux_elf_self_modifying_executable
{
    meta:
        author      = "usulnet"
        description = "ELF binary using runtime executable mapping (mprotect + RWX) often seen in packers / shellcode runners"
        severity    = "medium"
        family      = "packed"
        reference   = "https://attack.mitre.org/techniques/T1027/002/"

    strings:
        $mprotect       = "mprotect" ascii
        $mmap_anon      = "mmap" ascii
        $execve_self    = "/proc/self/exe" ascii
        $proc_mem       = "/proc/self/mem" ascii
        $memfd_create   = "memfd_create" ascii
        $magic_elf      = { 7F 45 4C 46 }

    condition:
        $magic_elf at 0 and $mprotect and ($memfd_create or $proc_mem or $execve_self)
}

rule linux_elf_credential_theft_paths
{
    meta:
        author      = "usulnet"
        description = "ELF binary embedding paths to credential / SSH / browser secrets"
        severity    = "high"
        family      = "credential_access"
        reference   = "https://attack.mitre.org/techniques/T1552/"

    strings:
        $shadow     = "/etc/shadow" ascii
        $ssh_priv   = ".ssh/id_rsa" ascii
        $ssh_keys   = ".ssh/authorized_keys" ascii
        $aws_creds  = ".aws/credentials" ascii
        $docker_cfg = ".docker/config.json" ascii
        $chrome     = "Login Data" ascii
        $magic_elf  = { 7F 45 4C 46 }

    condition:
        $magic_elf at 0 and 2 of ($shadow, $ssh_*, $aws_creds, $docker_cfg, $chrome)
}
