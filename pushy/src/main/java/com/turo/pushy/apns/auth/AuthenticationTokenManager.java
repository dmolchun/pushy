package com.turo.pushy.apns.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;

public class AuthenticationTokenManager {
    protected static final Logger log = LoggerFactory.getLogger(AuthenticationTokenManager.class);

    protected final ApnsSigningKey signingKey;
    protected AuthenticationToken authenticationToken;

    public AuthenticationTokenManager(ApnsSigningKey signingKey) {
        this.signingKey = signingKey;
    }

    public AuthenticationToken getAuthenticationToken() {
        if (authenticationToken == null) {
            try {
                this.authenticationToken = new AuthenticationToken(signingKey, new Date());
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                // This should never happen because we check the key/algorithm at signing key construction time.
                log.error("Failed to generate authentication token.", e);
                throw new RuntimeException(e);
            }
        }
        return this.authenticationToken;
    }

    public void setTokenExpired() {
        this.authenticationToken = null;
    }

    public boolean isTokenExpired() {
        return authenticationToken == null;
    }
}
