package com.alness.template.security.configuration;

import java.security.Key;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JwtTokenConfig {
    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    public static final String PREFIX_TOKEN = "Bearer ";

    private JwtTokenConfig() {
        throw new IllegalStateException("Utility class");
    }
}
