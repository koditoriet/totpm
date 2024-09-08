use std::{process::{Child, Command}, thread, time::Duration};
use rand::Rng;
use tempfile::TempDir;

pub struct SwTpm {
    process: Child,
    #[allow(dead_code)]
    dir: TempDir,
    pub tcti: String,
}

impl Drop for SwTpm {
    fn drop(&mut self) {
        self.process.kill().unwrap();
    }
}

impl Default for SwTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl SwTpm {
    pub fn new() -> Self {
        let tpm_dir = tempfile::tempdir().unwrap();
        for _ in 1..10 {
            let server_port: u16 = rand::thread_rng().gen_range(1024..65534);
            let mut child = Command::new("swtpm")
                .arg("socket")
                .arg("--tpmstate").arg(format!("dir={}", tpm_dir.path().to_str().unwrap()))
                .arg("--server").arg(format!("type=tcp,port={}", server_port))
                .arg("--ctrl").arg(format!("type=tcp,port={}", server_port+1))
                .arg("--tpm2")
                .arg("--flags").arg("not-need-init")
                .spawn()
                .unwrap();

            // Rerun swtpm if it terminated for some reason (most likely port collision)
            thread::sleep(Duration::from_millis(50));
            if let Ok(Some(_)) = child.try_wait() {
                continue;
            } else {
                return SwTpm {
                    process: child,
                    dir: tpm_dir,
                    tcti: format!("swtpm:host=127.0.0.1,port={}", server_port),
                };
            }
        }
        panic!("couldn't start swtpm");
    }
}
