pub mod model;

use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path};

use model::Secret;
use rusqlite::{params, Connection, Row, Transaction};

pub struct DB<'a> {
    transaction: Transaction<'a>
}

#[derive(Debug)]
pub enum Error {
    SqliteError(rusqlite::Error),
    IOError(std::io::Error),
    NoSuchElement,
}

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::SqliteError(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl <'a> DB<'a> {
    fn new(tx: Transaction<'a>) -> Self {
        DB {
            transaction: tx
        }
    }

    pub fn add_secret(&self, mut secret: Secret) -> Result<Secret> {
        self.transaction.execute("
            INSERT INTO secrets
                (service, account, digits, interval, public_data, private_data)
            VALUES
                (?1, ?2, ?3, ?4, ?5, ?6)
            ",
            params![
                secret.service.as_str(),
                secret.account.as_str(),
                secret.digits,
                secret.interval,
                secret.public_data,
                secret.private_data,
            ]
        )?;
        secret.id = self.transaction.last_insert_rowid();
        Ok(secret)
    }
    
    pub fn del_secret(&self, secret_id: i64) -> Result<()> {
        let affected_rows = self.transaction.execute("DELETE FROM secrets WHERE id = ?1", [secret_id])?;
        if affected_rows != 1 {
            Err(Error::NoSuchElement)
        } else {
            Ok(())
        }
    }
    
    pub fn list_secrets(&self, service: &str, account: &str) -> Result<Vec<Secret>> {
        let mut stmt = self.transaction.prepare("
            SELECT id, service, account, digits, interval, public_data, private_data
            FROM secrets
            WHERE service LIKE CONCAT('%', ?1, '%') AND ACCOUNT LIKE CONCAT('%', ?2, '%')
        ")?;
        let secrets = stmt.query_map([service, account], to_secret)
            ?.filter_map(core::result::Result::ok);
        Ok(secrets.collect())
    }
    
    pub fn get_secret(&self, secret_id: i64) -> Result<Secret> {
        self.transaction.query_row(
            "SELECT id, service, account, digits, interval, public_data, private_data FROM secrets WHERE id = ?1",
            [secret_id],
            to_secret
        ).map_err(From::from)
    }
}

pub fn with_db<P : AsRef<Path>, T, F: FnOnce(&DB) -> Result<T>>(db_path: P, f: F) -> Result<T> {
    ensure_db_dir_exists(&db_path)?;
    log::info!("opening connection to database {}", db_path.as_ref().to_str().unwrap());
    let mut db = Connection::open(&db_path)?;

    log::info!("starting transaction");
    let transaction = db.transaction()?;
    ensure_tables_exist(&transaction)?;
    let db = DB::new(transaction);
    let result = f(&db);
    if result.is_ok() {
        log::info!("committing transaction");
        db.transaction.commit()?;
    } else {
        log::info!("rolling back transaction");
        db.transaction.rollback()?;
    }
    result
}

fn ensure_db_dir_exists<P : AsRef<Path>>(db_path: P) -> Result<()> {
    let db_dir = db_path.as_ref().parent().unwrap();
    log::info!("creating secrets database directory with permissions 0700 at {}", db_dir.to_str().unwrap());
    std::fs::create_dir_all(&db_dir)?;
    std::fs::set_permissions(&db_dir, Permissions::from_mode(0o700))?;
    Ok(())
}

fn to_secret(row: &Row) -> rusqlite::Result<Secret> {
    Ok(Secret {
        id: row.get(0)?,
        service: row.get(1)?,
        account: row.get(2)?,
        digits: row.get(3)?,
        interval: row.get(4)?,
        public_data: row.get(5)?,
        private_data: row.get(6)?,
    })
}

fn ensure_tables_exist(tr: &Transaction) -> Result<()> {
    tr.execute("
        CREATE TABLE IF NOT EXISTS secrets (
            id           INTEGER PRIMARY KEY,
            service      TEXT NOT NULL,
            account      TEXT NOT NULL,
            digits       INTEGER NOT NULL,
            interval     INTEGER NOT NULL,
            public_data  BLOB NOT NULL,
            private_data BLOB NOT NULL
        )",
        (),
    )?;
    Ok(())
}
