/*
 * Copyright (c) 2013-2017 Turo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.turo.pushy.apns;

import com.turo.pushy.apns.auth.AuthenticationTokenManager;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http2.Http2ConnectionDecoder;
import io.netty.handler.codec.http2.Http2ConnectionEncoder;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2Settings;
import io.netty.util.AsciiString;
import java.util.Objects;

class TokenAuthenticationApnsClientHandler extends ApnsClientHandler {

    private final AuthenticationTokenManager tokenManager;

    private int mostRecentStreamWithNewToken = 0;

    private static final AsciiString APNS_AUTHORIZATION_HEADER = new AsciiString("authorization");

    private static final String EXPIRED_AUTH_TOKEN_REASON = "ExpiredProviderToken";

    public static class TokenAuthenticationApnsClientHandlerBuilder extends ApnsClientHandlerBuilder {
        private AuthenticationTokenManager tokenManager;

        public TokenAuthenticationApnsClientHandlerBuilder tokenManager(final AuthenticationTokenManager tokenManager) {
            this.tokenManager = tokenManager;
            return this;
        }

        public AuthenticationTokenManager tokenManager() {
            return this.tokenManager;
        }

        @Override
        public ApnsClientHandler build(final Http2ConnectionDecoder decoder, final Http2ConnectionEncoder encoder, final Http2Settings initialSettings) {
            Objects.requireNonNull(this.authority(), "Authority must be set before building a TokenAuthenticationApnsClientHandler.");
            Objects.requireNonNull(this.tokenManager(), "Token manager must be set before building a TokenAuthenticationApnsClientHandler.");

            final ApnsClientHandler handler = new TokenAuthenticationApnsClientHandler(decoder, encoder, initialSettings, this.authority(), this.tokenManager(), this.idlePingIntervalMillis());
            this.frameListener(handler);
            return handler;
        }
    }

    protected TokenAuthenticationApnsClientHandler(final Http2ConnectionDecoder decoder, final Http2ConnectionEncoder encoder, final Http2Settings initialSettings, final String authority, final AuthenticationTokenManager tokenManager, final long idlePingIntervalMillis) {
        super(decoder, encoder, initialSettings, authority, idlePingIntervalMillis);

        Objects.requireNonNull(tokenManager, "Token manager must not be null for token-based client handlers.");
        this.tokenManager = tokenManager;
    }

    @Override
    protected Http2Headers getHeadersForPushNotification(final ApnsPushNotification pushNotification, final int streamId) {
        final Http2Headers headers = super.getHeadersForPushNotification(pushNotification, streamId);

        if (this.tokenManager.isTokenExpired()) {
            this.mostRecentStreamWithNewToken = streamId;
        }

        headers.add(APNS_AUTHORIZATION_HEADER, this.tokenManager.getAuthenticationToken().getAuthorizationHeader());

        return headers;
    }

    @Override
    protected void handleErrorResponse(final ChannelHandlerContext context, final int streamId, final Http2Headers headers, final ApnsPushNotification pushNotification, final ErrorResponse errorResponse) {
        if (TokenAuthenticationApnsClientHandler.EXPIRED_AUTH_TOKEN_REASON.equals(errorResponse.getReason())) {
            if (streamId >= this.mostRecentStreamWithNewToken) {
                this.tokenManager.setTokenExpired();
            }

            // Once we've invalidated an expired token, it's reasonable to expect that re-sending the notification might
            // succeed.
            this.retryPushNotificationFromStream(context, streamId);
        } else {
            super.handleErrorResponse(context, streamId, headers, pushNotification, errorResponse);
        }
    }
}
