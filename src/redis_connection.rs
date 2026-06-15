use anyhow::Context;
use redis::IntoConnectionInfo;

pub(crate) fn connection_info(
    redis_url: &str,
    redis_password: Option<&str>,
    invalid_url_context: &'static str,
) -> anyhow::Result<redis::ConnectionInfo> {
    let mut connection_info = redis_url
        .into_connection_info()
        .context(invalid_url_context)?;

    if let Some(password) = redis_password
        .map(str::trim)
        .filter(|password| !password.is_empty())
    {
        let redis_settings = connection_info
            .redis_settings()
            .clone()
            .set_password(password);
        connection_info = connection_info.set_redis_settings(redis_settings);
    }

    Ok(connection_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_password_overrides_url_password_and_preserves_database() {
        let connection_info = connection_info(
            "redis://:url-secret@127.0.0.1:6379/2",
            Some(" configured-secret "),
            "invalid Redis URL",
        )
        .unwrap();

        assert_eq!(
            connection_info.redis_settings().password(),
            Some("configured-secret")
        );
        assert_eq!(connection_info.redis_settings().db(), 2);
    }

    #[test]
    fn absent_or_blank_password_preserves_url_password() {
        for password in [None, Some("  ")] {
            let connection_info = connection_info(
                "redis://:url-secret@127.0.0.1:6379",
                password,
                "invalid Redis URL",
            )
            .unwrap();

            assert_eq!(
                connection_info.redis_settings().password(),
                Some("url-secret")
            );
        }
    }

    #[test]
    fn invalid_url_uses_caller_context() {
        let error = connection_info("not a Redis URL", None, "configured Redis URL is invalid")
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("configured Redis URL is invalid"));
    }
}
