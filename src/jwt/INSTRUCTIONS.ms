1 - Create a JwtConfiguration with decoding_key and audience ( a Option<Vec<String>>) the JwtConfiguration should be paired with a generic to deserialize the jwt
2 - Create a JwtConfigurationBuilder that is able to use oidc autodiscover, or jwks uri as an alternative to with_deconding_key and with_audience
3 - Create a JwtLayer to inject an optional extractable struct that implements the same JwtConfiguration generic


