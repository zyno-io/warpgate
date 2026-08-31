use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Older application builds persisted this enum value using its Rust
        // snake_case spelling. CredentialKind has always deserialized the API
        // value as `publickey`, so those rows prevent the owning user from
        // loading after an upgrade. Replace only the JSON string token and
        // preserve every other credential-policy setting.
        let db = manager.get_connection();

        match manager.get_database_backend() {
            DbBackend::Postgres => {
                db.execute_unprepared(
                    "UPDATE users \\
                     SET credential_policy = REPLACE(credential_policy::text, '\"public_key\"', '\"publickey\"')::jsonb \\
                     WHERE credential_policy::text LIKE '%\"public_key\"%'",
                )
                .await?;
            }
            DbBackend::MySql => {
                db.execute_unprepared(
                    "UPDATE users \\
                     SET credential_policy = REPLACE(credential_policy, '\"public_key\"', '\"publickey\"') \\
                     WHERE CAST(credential_policy AS CHAR) LIKE '%\"public_key\"%'",
                )
                .await?;
            }
            DbBackend::Sqlite => {
                db.execute_unprepared(
                    "UPDATE users \\
                     SET credential_policy = REPLACE(credential_policy, '\"public_key\"', '\"publickey\"') \\
                     WHERE credential_policy LIKE '%\"public_key\"%'",
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // This is a compatibility repair. Reintroducing an enum spelling that
        // current releases cannot deserialize would make a downgraded database
        // unusable, so the data migration intentionally does not reverse.
        Ok(())
    }
}
