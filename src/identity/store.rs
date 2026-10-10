use super::crypto::equal;
use nddev_device_sync_application::identity::*;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::future::Future;

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}
type Tx<'a> = Transaction<'a, Postgres>;
fn unavailable<E>(_: E) -> IdentityError {
    IdentityError::Unavailable
}
fn millis(value: u64) -> Result<i64, IdentityError> {
    value.try_into().map_err(|_| IdentityError::InvalidInput)
}
fn unsigned(value: i64) -> Result<u64, IdentityError> {
    value.try_into().map_err(unavailable)
}
fn digest(value: Vec<u8>) -> Result<ProtectedDigest, IdentityError> {
    Ok(ProtectedDigest(value.try_into().map_err(unavailable)?))
}

async fn bounded<T>(
    work: impl Future<Output = Result<T, IdentityError>>,
) -> Result<T, IdentityError> {
    tokio::time::timeout(crate::database::DATABASE_TIMEOUT, work)
        .await
        .map_err(unavailable)?
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub(crate) async fn transaction(&self) -> Result<Tx<'_>, IdentityError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Personal-alpha issuance is serialized across processes. This one small
        // authority enforces capacity/rate/consume invariants without local caches.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(0x4e44533241555448_i64)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        Ok(tx)
    }
    pub async fn bootstrap(
        &self,
        email: ProtectedDigest,
        github_id: Option<u64>,
    ) -> Result<Owner, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            sqlx::query("INSERT INTO nds_owner(singleton,user_id,tenant_id,email_binding,github_id) VALUES (1,$1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(uuid::Uuid::new_v4().to_string()).bind(uuid::Uuid::new_v4().to_string()).bind(email.0.as_slice()).bind(github_id.map(millis).transpose()?).execute(&mut *tx).await.map_err(unavailable)?;
            let row = sqlx::query("SELECT user_id,tenant_id,email_binding,github_id FROM nds_owner WHERE singleton=1").fetch_one(&mut *tx).await.map_err(unavailable)?;
            let stored_github: Option<i64> = row.try_get("github_id").map_err(unavailable)?;
            if !equal(&digest(row.try_get("email_binding").map_err(unavailable)?)?, &email) || stored_github.map(unsigned).transpose()? != github_id { return Err(IdentityError::Denied); }
            let owner = Owner { user_id: UserId::new(row.try_get::<String,_>("user_id").map_err(unavailable)?).map_err(unavailable)?, tenant_id: TenantId::new(row.try_get::<String,_>("tenant_id").map_err(unavailable)?).map_err(unavailable)? };
            tx.commit().await.map_err(unavailable)?;
            Ok(owner)
        }).await
    }
}

pub(crate) async fn clean(tx: &mut Tx<'_>, now: u64) -> Result<(), IdentityError> {
    let now = millis(now)?;
    sqlx::query("DELETE FROM nds_auth_limits WHERE ends_at_ms <= $1")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("DELETE FROM nds_email_challenges WHERE expires_at_ms <= $1")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    sqlx::query("DELETE FROM nds_sessions WHERE expires_at_ms <= $1")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn rate(
    tx: &mut Tx<'_>,
    key: ProtectedDigest,
    policy: RatePolicy,
    now: u64,
) -> Result<(), IdentityError> {
    let row = sqlx::query("SELECT count,ends_at_ms FROM nds_auth_limits WHERE key=$1 FOR UPDATE")
        .bind(key.0.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
    let mut window = match row {
        Some(row) => RateWindow {
            count: row
                .try_get::<i32, _>("count")
                .map_err(unavailable)?
                .try_into()
                .map_err(unavailable)?,
            ends_at_ms: unsigned(row.try_get("ends_at_ms").map_err(unavailable)?)?,
        },
        None => {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_auth_limits")
                .fetch_one(&mut **tx)
                .await
                .map_err(unavailable)?;
            if count as usize >= MAX_RATE_KEYS {
                return Err(IdentityError::Capacity);
            }
            RateWindow::default()
        }
    };
    window.admit(now, policy)?;
    sqlx::query("INSERT INTO nds_auth_limits(key,count,ends_at_ms) VALUES ($1,$2,$3) ON CONFLICT(key) DO UPDATE SET count=EXCLUDED.count,ends_at_ms=EXCLUDED.ends_at_ms")
        .bind(key.0.as_slice()).bind(window.count as i32).bind(millis(window.ends_at_ms)?).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}

async fn insert_session(tx: &mut Tx<'_>, issue: SessionIssue) -> Result<Session, IdentityError> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_sessions")
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)?;
    if count as usize >= MAX_SESSIONS {
        return Err(IdentityError::Capacity);
    }
    sqlx::query("INSERT INTO nds_sessions(token_digest,user_id,tenant_id,auth_method,expires_at_ms) VALUES ($1,$2,$3,$4,$5)")
        .bind(issue.digest.0.as_slice()).bind(issue.session.owner.user_id.as_str()).bind(issue.session.owner.tenant_id.as_str())
        .bind(match issue.session.method { AuthMethod::EmailOtp => "email_otp", AuthMethod::Github => "github" }).bind(millis(issue.session.expires_at_ms)?).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(issue.session)
}

impl IdentityStore for Store {
    async fn issue_email(&self, issue: EmailIssue) -> Result<bool, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            let now = issue.created_at_ms;
            clean(&mut tx, now).await?;
            rate(&mut tx, issue.source, START_RATE, now).await?;
            // A suppressed resend returns the same generic receipt. Its source
            // budget still commits so repeated suppressed requests remain bounded.
            let newest: Option<i64> = sqlx::query_scalar("SELECT max(created_at_ms) FROM nds_email_challenges WHERE subject=$1")
                .bind(issue.subject.0.as_slice()).fetch_one(&mut *tx).await.map_err(unavailable)?;
            if newest.is_some_and(|created| now.saturating_sub(created as u64) < OTP_RESEND_MS) {
                tx.commit().await.map_err(unavailable)?;
                return Ok(false);
            }
            let admitted = rate(&mut tx, issue.subject, SUBJECT_RATE, now).await;
            if let Err(IdentityError::RateLimited) = admitted {
                tx.commit().await.map_err(unavailable)?;
                return Ok(false);
            }
            admitted?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nds_email_challenges").fetch_one(&mut *tx).await.map_err(unavailable)?;
            if count as usize >= MAX_PENDING_EMAIL { return Err(IdentityError::Capacity); }
            sqlx::query("DELETE FROM nds_email_challenges WHERE subject=$1").bind(issue.subject.0.as_slice()).execute(&mut *tx).await.map_err(unavailable)?;
            sqlx::query("INSERT INTO nds_email_challenges(challenge_id,subject,verifier,created_at_ms,expires_at_ms,attempts_remaining,eligible,consumed) VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE)")
                .bind(&issue.id).bind(issue.subject.0.as_slice()).bind(issue.verifier.0.as_slice()).bind(millis(now)?).bind(millis(issue.challenge.expires_at_ms)?)
                .bind(issue.challenge.attempts_remaining as i16).bind(issue.challenge.eligible).execute(&mut *tx).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)?;
            Ok(true)
        }).await
    }
    async fn invalidate_email(&self, id: &str) -> Result<(), IdentityError> {
        bounded(async {
            sqlx::query("UPDATE nds_email_challenges SET consumed=TRUE WHERE challenge_id=$1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(unavailable)?;
            Ok(())
        })
        .await
    }
    async fn consume_email(
        &self,
        id: &str,
        verifier: ProtectedDigest,
        source: ProtectedDigest,
        issue: SessionIssue,
        now: u64,
    ) -> Result<Session, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            clean(&mut tx, now).await?;
            rate(&mut tx, source, VERIFY_RATE, now).await?;
            let row = sqlx::query("SELECT verifier,expires_at_ms,attempts_remaining,eligible,consumed FROM nds_email_challenges WHERE challenge_id=$1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await.map_err(unavailable)?;
            let Some(row) = row else { tx.commit().await.map_err(unavailable)?; return Err(IdentityError::Denied); };
            let mut challenge = OtpChallenge { expires_at_ms: unsigned(row.try_get("expires_at_ms").map_err(unavailable)?)?, attempts_remaining: row.try_get::<i16,_>("attempts_remaining").map_err(unavailable)?.try_into().map_err(unavailable)?, eligible: row.try_get("eligible").map_err(unavailable)?, consumed: row.try_get("consumed").map_err(unavailable)? };
            let matches = equal(&digest(row.try_get("verifier").map_err(unavailable)?)?, &verifier);
            let accepted = challenge.consume(now, matches);
            sqlx::query("UPDATE nds_email_challenges SET attempts_remaining=$2,consumed=$3 WHERE challenge_id=$1").bind(id).bind(challenge.attempts_remaining as i16).bind(challenge.consumed).execute(&mut *tx).await.map_err(unavailable)?;
            let outcome = match accepted { Ok(()) => insert_session(&mut tx, issue).await, Err(error) => Err(error) };
            // Denied verification commits attempts. Capacity failure rolls back
            // the entire consumption, allowing correct reauthentication later.
            if matches!(outcome, Err(IdentityError::Capacity | IdentityError::Unavailable)) { return outcome; }
            tx.commit().await.map_err(unavailable)?;
            outcome
        }).await
    }
    async fn create_session(
        &self,
        issue: SessionIssue,
        now: u64,
    ) -> Result<Session, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            clean(&mut tx, now).await?;
            let session = insert_session(&mut tx, issue).await?;
            tx.commit().await.map_err(unavailable)?;
            Ok(session)
        })
        .await
    }
    async fn session(&self, token: ProtectedDigest, now: u64) -> Result<Session, IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            // An observed expiry is deleted, so clock rollback cannot revive it.
            sqlx::query("DELETE FROM nds_sessions WHERE token_digest=$1 AND expires_at_ms <= $2").bind(token.0.as_slice()).bind(millis(now)?).execute(&mut *tx).await.map_err(unavailable)?;
            let row = sqlx::query("SELECT user_id,tenant_id,auth_method,expires_at_ms FROM nds_sessions WHERE token_digest=$1 AND expires_at_ms > $2").bind(token.0.as_slice()).bind(millis(now)?).fetch_optional(&mut *tx).await.map_err(unavailable)?;
            // Denial must not roll back the observed-expiry deletion.
            tx.commit().await.map_err(unavailable)?;
            let row = row.ok_or(IdentityError::Denied)?;
            Ok(Session { owner: Owner { user_id: UserId::new(row.try_get::<String,_>("user_id").map_err(unavailable)?).map_err(unavailable)?, tenant_id: TenantId::new(row.try_get::<String,_>("tenant_id").map_err(unavailable)?).map_err(unavailable)? }, method: match row.try_get::<&str,_>("auth_method").map_err(unavailable)? { "email_otp"=>AuthMethod::EmailOtp,"github"=>AuthMethod::Github,_=>return Err(IdentityError::Unavailable) }, expires_at_ms: unsigned(row.try_get("expires_at_ms").map_err(unavailable)?)? })
        }).await
    }
    async fn revoke(&self, token: ProtectedDigest, now: u64) -> Result<(), IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            let expiry: Option<i64> = sqlx::query_scalar(
                "DELETE FROM nds_sessions WHERE token_digest=$1 RETURNING expires_at_ms",
            )
            .bind(token.0.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)?;
            if expiry
                .map(unsigned)
                .transpose()?
                .is_some_and(|expiry| now < expiry)
            {
                Ok(())
            } else {
                Err(IdentityError::Denied)
            }
        })
        .await
    }
    async fn admit_source(
        &self,
        source: ProtectedDigest,
        policy: RatePolicy,
        now: u64,
    ) -> Result<(), IdentityError> {
        bounded(async {
            let mut tx = self.transaction().await?;
            clean(&mut tx, now).await?;
            rate(&mut tx, source, policy, now).await?;
            tx.commit().await.map_err(unavailable)?;
            Ok(())
        })
        .await
    }
}
