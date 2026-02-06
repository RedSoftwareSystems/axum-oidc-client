use futures_util::future::BoxFuture;

use crate::auth_session::AuthSession;
use crate::errors::Error;

pub trait AuthCache {
    fn get_code_verifier(
        &self,
        challenge_state: &str,
    ) -> BoxFuture<'_, Result<Option<String>, Error>>;
    fn set_code_verifier(
        &self,
        challenge_state: &str,
        code_verifier: &str,
    ) -> BoxFuture<'_, Result<(), Error>>;
    fn invalidate_code_verifier(&self, challenge_state: &str) -> BoxFuture<'_, Result<(), Error>>;

    fn get_auth_session(&self, id: &str) -> BoxFuture<'_, Result<Option<AuthSession>, Error>>;
    fn set_auth_session(&self, id: &str, session: AuthSession) -> BoxFuture<'_, Result<(), Error>>;
    fn invalidate_auth_session(&self, id: &str) -> BoxFuture<'_, Result<(), Error>>;
    fn extend_auth_session(&self, id: &str, ttl: i64) -> BoxFuture<'_, Result<(), Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that AuthCache can be used as a trait object
    #[test]
    fn test_dyn_compatible() {
        fn accepts_trait_object(_cache: Box<dyn AuthCache>) {
            // This function exists only to verify that AuthCache can be used as a trait object
        }

        fn accepts_ref_trait_object(_cache: &dyn AuthCache) {
            // This function exists only to verify that AuthCache can be used as a trait object reference
        }

        // If this compiles, the trait is object-safe
        let _ = accepts_trait_object;
        let _ = accepts_ref_trait_object;
    }
}
