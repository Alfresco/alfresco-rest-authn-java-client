/*
 * Copyright 2019 Alfresco Software, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.alfresco.rest.authn;

import static org.junit.Assert.assertNotNull;

import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.alfresco.rest.authn.exception.AuthenticationException;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.AccessTokenResponse;

/**
 * @author Jamal Kaabi-Mofrad
 */
public class AccessTokenTestIT
{

    @Test
    public void testGetToken()
    {
        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder().build();
        TokenProvider tokenProvider = new TokenProvider(authnConfigBuilder);

        AccessTokenResponse tokenResponse = tokenProvider.getAccessToken();
        assertNotNull(tokenResponse);
        assertNotNull(tokenResponse.getToken());
        assertNotNull(tokenResponse.getRefreshToken());
    }

    @Test(expected = AuthenticationException.class)
    public void testGetTokenFail()
    {
        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder().build();
        TokenProvider tokenProvider = new TokenProvider(authnConfigBuilder);

        tokenProvider.getAccessToken("testUSer", "testPassword" + System.currentTimeMillis());
    }

    @Test(expected = AuthenticationException.class)
    public void testVerifyModifiedToken()
    {
        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder().build();
        TokenProvider tokenProvider = new TokenProvider(authnConfigBuilder);

        AccessTokenResponse tokenResponse = tokenProvider.getAccessToken();
        assertNotNull(tokenResponse);
        assertNotNull(tokenResponse.getToken());

        String[] jwtComponents = tokenResponse.getToken().split("\\.");
        String base64EncodedHeader = jwtComponents[0];
        String base64EncodedBody = jwtComponents[1];
        String base64EncodedSignature = jwtComponents[2];

        // Decode the body and manipulate the expiry time
        String body = new String(Base64.getUrlDecoder().decode(base64EncodedBody));
        String modifiedBody = body.replaceFirst("(\"exp\":)[0-9]+", "\"exp\":"
                    + TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() + 5000));

        // Encode the body again
        byte[] encodedBody = Base64.getUrlEncoder().encode(modifiedBody.getBytes());

        // Construct the encoded JWT token
        String modifiedToken = base64EncodedHeader + "." + new String(encodedBody) + "." + base64EncodedSignature;
        // Should through Invalid token signature as we modified
        // the body and the signatures don't match anymore.
        tokenProvider.verifyToken(modifiedToken);
    }

    @Test(expected = AuthenticationException.class)
    public void testGetTokenUnsupportedGrantType()
    {
        Properties properties = new Properties();
        properties.setProperty("alfresco.identity.service.grant-type", OAuth2Constants.AUTHORIZATION_CODE);

        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(properties).build();
        TokenProvider tokenProvider = new TokenProvider(authnConfigBuilder);

        tokenProvider.getAccessToken();
    }
}
