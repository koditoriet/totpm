#[link(name = "c")]
extern "C" {
    fn setresuid(ruid: u32, euid: u32, suid: u32) -> u32;
    fn getuid() -> u32;
    fn getgid() -> u32;
    fn geteuid() -> u32;
    fn seteuid(uid: u32) -> u32;
    fn setegid(uid: u32) -> u32;
}

/// Set all UIDs to our real UID, dropping any SUID-acquired privileges.
/// Returns true if dropping privileges succeeded, otherwise false.
pub fn drop_privileges() -> bool {
    log::info!("permanently dropping privileges");
    unsafe {
        let euid = geteuid();

        // Drop privileges
        let gid = getgid();
        let uid = getuid();
        setegid(gid);
        setresuid(uid, uid, uid);
        
        // Ensure we can't change back to our old EUID
        seteuid(euid);
        geteuid() == uid
    }
}

/// Temporarily assume our real UID as our effective UID.
pub fn with_uid_as_euid<T, F: FnOnce() -> T>(f: F) -> T {
    unsafe {
        let uid = getuid();
        let euid = geteuid();
        log::info!("setting euid to {} (was {})", uid, euid);
        seteuid(uid);
        let result = f();
        log::info!("restoring euid to {} (was {})", euid, uid);
        seteuid(euid);
        result
    }
}

pub fn is_root() -> bool {
    unsafe {
        getuid() == 0
    }
}

pub fn is_effective_user(uid: u32) -> bool {
    unsafe {
        geteuid() == uid
    }
}
