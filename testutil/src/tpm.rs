use std::process::{Child, Command};
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

impl SwTpm {
    pub fn new() -> Self {
        let tpm_dir = tempfile::tempdir().unwrap();
        let server_port: u16 = rand::thread_rng().gen_range(1024..65534);
        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpmstate").arg(format!("dir={}", tpm_dir.path().to_str().unwrap()))
            .arg("--server").arg(format!("type=tcp,port={}", server_port))
            .arg("--ctrl").arg(format!("type=tcp,port={}", server_port+1))
            .arg("--tpm2")
            .arg("--flags").arg("not-need-init")
            .spawn()
            .unwrap();
        SwTpm {
            process: child,
            dir: tpm_dir,
            tcti: format!("swtpm:host=127.0.0.1,port={}", server_port),
        }
    }
}
