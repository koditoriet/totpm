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
    DbDirIsNotADir,
    DbFileIsNotAFile,
}

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        match value {
            rusqlite::Error::QueryReturnedNoRows => Self::NoSuchElement,
            _ => Self::SqliteError(value)
        }
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
    ensure_db_file_exists(&db_path)?;
    log::info!("creating database {} with secure permissions", db_path.as_ref().to_str().unwrap());
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

fn ensure_db_file_exists<P : AsRef<Path>>(db_path: P) -> Result<()> {
    let db_dir = db_path.as_ref().parent().unwrap();
    if !db_dir.exists() {
        log::info!("creating secrets database directory with permissions 0700 at {}", db_dir.to_str().unwrap());
        std::fs::create_dir_all(&db_dir)?;
    }
    if !db_dir.is_dir() {
        return Err(Error::DbDirIsNotADir);
    }
    if !db_path.as_ref().exists() {
        std::fs::File::create_new(&db_path)?;
        std::fs::set_permissions(&db_path, Permissions::from_mode(0o600))?;
    }
    if !db_path.as_ref().is_file() {
        Err(Error::DbFileIsNotAFile)
    } else {
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_db_ensures_db_dir_file_and_schema_are_created() {
        let dbdir = tempfile::tempdir().unwrap();
        let db = dbdir.path().join("db.sqlite");

        with_db(&db, |_| Ok(())).unwrap();
        dbg!(dbdir.path());
        assert!(&db.is_file());
        assert!(dbdir.path().is_dir());
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600,
        );

        let result = with_db(&db, |tx| tx.list_secrets("", "")).unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn db_file_always_has_secure_permissions() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let secret = Secret {
            id: 0,
            service: "svc".to_owned(),
            account: "acct".to_owned(),
            digits: 6,
            interval: 30,
            public_data: vec![],
            private_data: vec![],
        };

        with_db(&db, |_| Ok(())).unwrap();
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600,
        );

        with_db(&db, |tx| tx.add_secret(secret)).unwrap();
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600,
        );

        let secrets = with_db(&db, |tx| tx.list_secrets("", "")).unwrap();
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600,
        );

        with_db(&db, |tx| tx.del_secret(secrets[0].id)).unwrap();
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600,
        );

    }

    #[test]
    fn with_db_does_not_fail_if_db_dir_is_owned_by_someone_else() {
        let db = tempfile::NamedTempFile::new().unwrap();

        with_db(&db, |_| Ok(())).unwrap();
        assert!(&db.path().is_file());
    }

    #[test]
    fn with_db_fails_if_db_file_exists_but_is_not_a_file() {
        match with_db(Path::new("/dev/null"), |_| Ok(())) {
            Err(Error::DbFileIsNotAFile) => { /* everything is fine */ },
            Err(e) => { panic!("expected DbDirIsNotADir, but got {:#?}", e) },
            _ => { panic!("with_db did not fail when db dir was a file") }
        }
    }

    #[test]
    fn with_db_fails_if_db_dir_is_not_a_directory() {
        let db = tempfile::NamedTempFile::new().unwrap();

        let result = with_db(&db.path().join("db.sqlite"), |_| Ok(()));
        match result {
            Err(Error::DbDirIsNotADir) => { /* everything is fine */ },
            Err(e) => { panic!("expected DbDirIsNotADir, but got {:#?}", e) },
            _ => { panic!("with_db did not fail when db dir was a file") }
        }
    }

    #[test]
    fn transaction_is_rolled_back_on_error() {
        let secret = Secret {
            id: 0,
            service: "svc".to_owned(),
            account: "acct".to_owned(),
            digits: 6,
            interval: 30,
            public_data: vec![],
            private_data: vec![],
        };
        let db = tempfile::NamedTempFile::new().unwrap();
        let error = with_db(db.path(), |tx| {
            tx.add_secret(secret).unwrap();
            Err(Error::NoSuchElement) as Result<()>
        }).unwrap_err();
        match error {
            Error::NoSuchElement => { /* everything is fine */ },
            _ => { panic!("wrong error: {:#?}", error) }
        };

        let secrets = with_db(db.path(), |tx| tx.list_secrets("", "")).unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn transaction_is_committed_on_success() {
        let secret = Secret {
            id: 0,
            service: "svc".to_owned(),
            account: "acct".to_owned(),
            digits: 6,
            interval: 30,
            public_data: vec![],
            private_data: vec![],
        };
        let db = tempfile::NamedTempFile::new().unwrap();
        let inserted_secret = with_db(db.path(), |tx| tx.add_secret(secret)).unwrap();
        let secrets = with_db(db.path(), |tx| tx.list_secrets("", "")).unwrap();
        assert_eq!(vec![inserted_secret], secrets);
    }

    #[test]
    fn add_secret_auto_generates_insert_id() {
        let secret = Secret {
            id: 0,
            service: "svc".to_owned(),
            account: "acct".to_owned(),
            digits: 6,
            interval: 30,
            public_data: vec![],
            private_data: vec![],
        };
        let db = tempfile::NamedTempFile::new().unwrap();
        let inserted_secret_1 = with_db(db.path(), |tx| tx.add_secret(secret.clone())).unwrap();
        let inserted_secret_2 = with_db(db.path(), |tx| tx.add_secret(secret)).unwrap();
        assert_ne!(inserted_secret_1.id, 0);
        assert_ne!(inserted_secret_2.id, 0);
        assert_ne!(inserted_secret_1.id, inserted_secret_2.id);
    }

    #[test]
    fn add_secret_preserves_everything_but_id() {
        let mut secret = Secret {
            id: 0,
            service: "mame".to_owned(),
            account: "goma".to_owned(),
            digits: 7,
            interval: 19,
            public_data: vec![123,4],
            private_data: vec![5,6,7,8],
        };
        let db = tempfile::NamedTempFile::new().unwrap();
        let inserted_secret = with_db(db.path(), |tx| tx.add_secret(secret.clone())).unwrap();
        let stored_secret = with_db(db.path(), |tx| tx.get_secret(inserted_secret.id)).unwrap();

        secret.id = inserted_secret.id;
        assert_eq!(inserted_secret, secret);
        assert_eq!(stored_secret, secret);
    }

    #[test]
    fn get_secret_returns_correct_secret() {
        let secret = Secret {
            id: 0,
            service: "svc".to_owned(),
            account: "acct".to_owned(),
            digits: 6,
            interval: 30,
            public_data: vec![],
            private_data: vec![],
        };
        let other_secret = Secret {
            id: 0,
            service: "mame".to_owned(),
            account: "goma".to_owned(),
            digits: 7,
            interval: 19,
            public_data: vec![123,4],
            private_data: vec![5,6,7,8],
        };
        let db = tempfile::NamedTempFile::new().unwrap();
        let expected_secret = with_db(db.path(), |tx| {
            tx.add_secret(secret.clone())?;
            tx.add_secret(secret.clone())?;
            let actual_secret = tx.add_secret(other_secret.clone())?;
            tx.add_secret(secret)?;
            Ok(actual_secret)
        }).unwrap();
        let actual_secret = with_db(db.path(), |tx| tx.get_secret(expected_secret.id)).unwrap();
        assert_eq!(actual_secret, expected_secret);
    }

    #[test]
    fn list_secrets_returns_correct_secrets() {
        let mut secret = Secret {
            id: 0,
            service: "svc".to_owned(),
            account: "acct".to_owned(),
            digits: 6,
            interval: 30,
            public_data: vec![],
            private_data: vec![],
        };
        let db = tempfile::NamedTempFile::new().unwrap();
        let all_ids = with_db(db.path(), |tx| {
            let mut ids = Vec::new();
            ids.push(tx.add_secret(secret.clone())?.id);
            secret.service = "service".to_owned();
            ids.push(tx.add_secret(secret.clone())?.id);
            secret.account = "account".to_owned();
            ids.push(tx.add_secret(secret.clone())?.id);
            secret.service = "tjänst".to_owned();
            secret.account = "konto".to_owned();
            ids.push(tx.add_secret(secret.clone())?.id);
            Ok(ids)
        }).unwrap();

        /* empty strings match all secrets */
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("", ""))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, all_ids);

        /* full match on service */
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("service", ""))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[1], all_ids[2]]);

        /* full match on account */
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("", "acct"))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[0], all_ids[1]]);

        /* full match on both service and account */
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("svc", "acct"))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[0]]);

        /* partial match on service */
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("tj", ""))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[3]]);
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("c", ""))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[0], all_ids[1], all_ids[2]]);
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("ce", ""))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[1], all_ids[2]]);

        /* partial match on account */
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("", "acc"))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[0], all_ids[1], all_ids[2]]);
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("", "cco"))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[2]]);
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("", "nto"))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![all_ids[3]]);

        /* no match */
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("potato", ""))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![]);
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("", "potato"))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![]);
        let ids: Vec<i64> = with_db(db.path(), |tx| tx.list_secrets("potato", "potato"))
            .unwrap().iter().map(|x| x.id).collect();
        assert_eq!(ids, vec![]);
    }

    #[test]
    fn get_secret_fails_if_id_does_not_exist() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let error = with_db(db.path(), |tx| tx.get_secret(1)).unwrap_err();
        match error {
            Error::NoSuchElement => { /* everything is fine */ },
            _ => { panic!("wrong error: {:#?}", error) }
        };
    }

    #[test]
    fn del_secret_fails_if_id_does_not_exist() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let error = with_db(db.path(), |tx| tx.del_secret(1)).unwrap_err();
        match error {
            Error::NoSuchElement => { /* everything is fine */ },
            _ => { panic!("wrong error: {:#?}", error) }
        };
    }

    #[test]
    fn del_secret_only_affects_secret_with_given_id() {
        let mut secret = Secret {
            id: 0,
            service: "mame".to_owned(),
            account: "goma".to_owned(),
            digits: 7,
            interval: 19,
            public_data: vec![123,4],
            private_data: vec![5,6,7,8],
        };
        let db = tempfile::NamedTempFile::new().unwrap();
        let secret_id = with_db(db.path(), |tx| {
            tx.add_secret(secret.clone())?;
            tx.add_secret(secret.clone())?;
            secret.service = "DELETE THIS ONE".to_owned();
            tx.add_secret(secret.clone())
        }).unwrap().id;
        let result = with_db(db.path(), |tx| {
            tx.del_secret(secret_id)?;
            tx.list_secrets("", "")
        }).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result.iter().find(|x| x.service != "mame"), None);
        assert_eq!(result.iter().find(|x| x.id == secret_id), None);
    }
}
