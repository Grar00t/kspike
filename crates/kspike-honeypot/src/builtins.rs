//! Built-in profiles.

use crate::profile::{HoneypotProfile, OsFamily, RetentionPolicy};

pub fn meterpreter_win10_x64() -> HoneypotProfile {
    HoneypotProfile {
        name: "meterpreter_win10_x64".into(),
        os: OsFamily::Windows,
        hostname: "WIN10-FINANCE-7".into(),
        banner: "Windows 10 Pro 19045 (x64)\r\n".into(),
        open_ports: vec![135, 139, 445, 3389],
        fake_fs_sample: vec![
            "C:\\Users\\finance\\Documents\\Q1-plans.docx".into(),
            "C:\\Users\\finance\\Desktop\\Passwords.txt".into(),   // classic canary
            "C:\\ProgramData\\Contoso\\License.key".into(),
        ],
        fake_users: vec!["finance".into(), "svc-backup".into(), "helpdesk.admin".into()],
        retention: RetentionPolicy {
            max_engagement_seconds: 1800,
            max_bytes: 2 * 1_048_576,
            teardown_hint: "The remote computer reset the connection.".into(),
        },
        forbidden_leaks: vec![
            // Never pretend to leak data that maps to a real organisation.
            "*.gov.sa".into(), "*.mil".into(), "*.icrc.org".into(),
            "*.hospital".into(), "*.edu".into(),
        ],
    }
}

pub fn ssh_ubuntu_2004() -> HoneypotProfile {
    HoneypotProfile {
        name: "ssh_ubuntu_2004".into(),
        os: OsFamily::Linux,
        hostname: "web01.canary.local".into(),
        banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n".into(),
        open_ports: vec![22],
        fake_fs_sample: vec![
            "/home/ubuntu/.ssh/authorized_keys".into(),
            "/var/www/html/config.php".into(),
        ],
        fake_users: vec!["ubuntu".into(), "deploy".into()],
        retention: RetentionPolicy::default(),
        forbidden_leaks: vec!["*.gov".into(), "*.mil".into()],
    }
}

pub fn smb_win7() -> HoneypotProfile {
    HoneypotProfile {
        name: "smb_win7".into(),
        os: OsFamily::Windows,
        hostname: "WIN7-LEGACY".into(),
        banner: "\\\\WIN7-LEGACY\r\n".into(),
        open_ports: vec![139, 445],
        fake_fs_sample: vec![
            "\\\\WIN7-LEGACY\\shared\\invoices\\2026-Q1.xlsx".into(),
            "\\\\WIN7-LEGACY\\admin$\\System32".into(),
        ],
        fake_users: vec!["Administrator".into(), "guest".into()],
        retention: RetentionPolicy::default(),
        forbidden_leaks: vec!["*.gov".into(), "*.mil".into()],
    }
}
