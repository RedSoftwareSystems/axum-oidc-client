//! Shared helper for constructing session cookies with consistent attributes.
//!
//! The session cookie is created (and refreshed) after a successful token
//! exchange and on subsequent requests, and removed on logout. All of these
//! call sites need the same `path`, `HttpOnly`, `SameSite`, and `Secure`
//! attributes, so the construction logic lives here to avoid drift between
//! them (e.g. if a `domain` attribute or a different `SameSite` policy is
//! introduced later, it only needs to change in one place).

use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

/// Builds a session cookie with the standard authentication attributes:
/// `path=/`, `HttpOnly`, `SameSite` (Lax or Strict), and `Secure`.
///
/// - `value: Some(v)` builds a name+value cookie suitable for `jar.add(...)`.
/// - `value: None` builds a name-only cookie suitable for `jar.remove(...)`,
///   which only needs to match the original cookie's attributes to be
///   deleted by the browser.
/// - `max_age: Some(duration)` sets the cookie to expire after `duration`;
///   `None` omits `max_age` entirely (used for removal, where an expiry is
///   meaningless). Callers are responsible for constructing the `Duration`
///   with the appropriate unit (e.g. `Duration::minutes(...)`).
pub(crate) fn build_session_cookie(
    name: &'static str,
    value: Option<String>,
    lax_same_site: bool,
    secure_cookies: bool,
    max_age: Option<Duration>,
) -> Cookie<'static> {
    let mut builder = match value {
        Some(v) => Cookie::build((name, v)),
        None => Cookie::build(name),
    }
    .path("/")
    .http_only(true)
    .same_site(if lax_same_site {
        SameSite::Lax
    } else {
        SameSite::Strict
    })
    .secure(secure_cookies);

    if let Some(duration) = max_age {
        builder = builder.max_age(duration);
    }

    builder.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_cookie_has_value_and_max_age() {
        let cookie = build_session_cookie(
            "AUTH_SESSION",
            Some("abc123".to_string()),
            false,
            true,
            Some(Duration::minutes(30)),
        );

        assert_eq!(cookie.name(), "AUTH_SESSION");
        assert_eq!(cookie.value(), "abc123");
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.max_age(), Some(Duration::minutes(30)));
    }

    #[test]
    fn remove_cookie_has_no_value_or_max_age() {
        let cookie = build_session_cookie("AUTH_SESSION", None, true, false, None);

        assert_eq!(cookie.name(), "AUTH_SESSION");
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.secure(), Some(false));
        assert_eq!(cookie.max_age(), None);
    }
}
