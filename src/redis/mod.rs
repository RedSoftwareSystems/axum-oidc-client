use futures_util::future::BoxFuture;
use redis::{AsyncTypedCommands, Client};

use crate::auth_cache;
use crate::auth_session::AuthSession;
use crate::errors::Error;

#[cfg(all(feature = "redis-native-tls", feature = "redis-rustls"))]
compile_error!(
    "feature \"redis-native-tls\" and feature \"redis-rustls\" cannot be enabled at the same time"
);
const CODE_TTL_SEC: u64 = 60;
pub struct AuthCache {
    pub client: Client,
    pub ttl_sec: u64,
}

impl AuthCache {
    pub fn new(uri: &str, ttl_sec: u64) -> Self {
        let client = redis::Client::open(uri).unwrap();
        Self { client, ttl_sec }
    }

    // helper to get a multiplexed connection
    async fn con(&self) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        self.client.get_multiplexed_async_connection().await
    }
}

impl auth_cache::AuthCache for AuthCache {
    fn get_code_verifier(
        &self,
        challenge_state: &str,
    ) -> BoxFuture<'_, Result<Option<String>, Error>> {
        let code_id = format!("code_verifier.{challenge_state}");
        Box::pin(async move {
            let mut con = self.con().await?;
            let cache_result = con.get(&code_id).await?;
            Ok(cache_result)
        })
    }

    fn set_code_verifier(
        &self,
        challenge_state: &str,
        code_verifier: &str,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let code_id = format!("code_verifier.{challenge_state}");
        let code_verifier = code_verifier.to_string();
        Box::pin(async move {
            let mut con = self.con().await?;
            con.set_ex(&code_id, code_verifier, CODE_TTL_SEC).await?;

            Ok(())
        })
    }

    fn invalidate_code_verifier(&self, challenge_state: &str) -> BoxFuture<'_, Result<(), Error>> {
        let code_id = format!("code_verifier.{challenge_state}");
        Box::pin(async move {
            let mut con = self.con().await?;
            con.del(&code_id).await?;
            Ok(())
        })
    }

    fn get_auth_session(
        &self,
        session_id: &str,
    ) -> BoxFuture<'_, Result<Option<AuthSession>, Error>> {
        let session_id = format!("session.{session_id}");
        Box::pin(async move {
            let mut con = self.con().await?;
            let cache_result = con.get(&session_id).await?.map(|v| {
                serde_json::from_str::<AuthSession>(&v)
                    .map_err(|e| Error::CacheError(e.to_string()))
            });

            match cache_result {
                Some(result) => {
                    let session = result?;
                    Ok(Some(session))
                }
                None => Ok(None),
            }
        })
    }

    fn set_auth_session(
        &self,
        session_id: &str,
        session: AuthSession,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let session_id = format!("session.{session_id}");
        Box::pin(async move {
            let mut con = self.con().await?;
            con.set_ex(&session_id, serde_json::to_string(&session)?, self.ttl_sec)
                .await?;

            Ok(())
        })
    }

    fn invalidate_auth_session(&self, session_id: &str) -> BoxFuture<'_, Result<(), Error>> {
        let session_id = format!("session.{session_id}");
        Box::pin(async move {
            let mut con = self.con().await?;
            con.del(&session_id).await?;
            Ok(())
        })
    }

    fn extend_auth_session(&self, session_id: &str, ttl: i64) -> BoxFuture<'_, Result<(), Error>> {
        let session_id = session_id.to_string();
        Box::pin(async move {
            let mut con = self.con().await?;
            con.expire(&session_id, ttl).await?;
            Ok(())
        })
    }
}
