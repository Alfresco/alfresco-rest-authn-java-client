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

import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.alfresco.rest.authn.config.IdentityServiceConfig;
import org.alfresco.rest.authn.exception.AuthenticationException;
import org.apache.http.client.HttpClient;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;

/**
 * Identity service access token provider.
 *
 * @author Jamal Kaabi-Mofrad
 */
public class TokenProvider
{
    private static final Logger LOGGER = Logger.getLogger(TokenProvider.class);

    private final IdentityServiceConfig config;
    private final KeycloakDeployment deployment;
    private final AuthzClient authzClient;

    public TokenProvider(AuthnConfigBuilder authnConfigBuilder)
    {
        this.config = authnConfigBuilder.getIdentityServiceConfig();
        this.deployment = KeycloakDeploymentBuilder.build(this.config);

        HttpClient httpClient = createHttpClient(this.config);
        deployment.setClient(httpClient);

        this.authzClient = createAuthzClient(this.config, httpClient);
    }

    private HttpClient createHttpClient(IdentityServiceConfig config)
    {
        return new HttpClientBuilder()
                    .establishConnectionTimeout(config.getClientConnectionTimeoutInMillis(), TimeUnit.MILLISECONDS)
                    .socketTimeout(config.getClientSocketTimeoutInMillis(), TimeUnit.MILLISECONDS)
                    .build(config);
    }

    private AuthzClient createAuthzClient(IdentityServiceConfig config, HttpClient httpClient)
    {
        Configuration authzConfig = new Configuration(config.getAuthServerUrl(),
                    config.getRealm(),
                    config.getResource(),
                    config.getCredentials(),
                    httpClient);
        AuthzClient authzClient = AuthzClient.create(authzConfig);

        if (LOGGER.isDebugEnabled())
        {
            LOGGER.debug("Created Keycloak AuthzClient:");
            LOGGER.debug("    Keycloak AuthzClient server URL: " + authzClient.getConfiguration().getAuthServerUrl());
            LOGGER.debug("    Keycloak AuthzClient realm: " + authzClient.getConfiguration().getRealm());
            LOGGER.debug("    Keycloak AuthzClient resource: " + authzClient.getConfiguration().getResource());
        }
        return authzClient;
    }

    /**
     * Gets the access token based on the configured {@code grant_type}.
     * <p>
     * If the {@code grant_type} is set to 'password', gets the access token using the configured username and password.
     * <p>
     * If the {@code grant_type} is set to 'client_credentials', gets the access token using the configured credentials secret.
     */
    public AccessTokenResponse getAccessToken()
    {
        String grantType = config.getGrantType();
        if (OAuth2Constants.PASSWORD.equals(grantType))
        {
            return getAccessToken(config.getUsername(), config.getPassword());
        }
        else if (OAuth2Constants.CLIENT_CREDENTIALS.equals(grantType))
        {
            return execute(authzClient::obtainAccessToken);
        }
        else
        {
            throw new AuthenticationException(grantType + " is an unsupported grant type. Supported grant types are: " + OAuth2Constants.PASSWORD + " and "
                        + OAuth2Constants.CLIENT_CREDENTIALS);
        }
    }

    /**
     * Gets access token using the given username and password.
     *
     * @param username the username
     * @param password the password
     */
    public AccessTokenResponse getAccessToken(final String username, final String password)
    {
        return execute(() -> authzClient.obtainAccessToken(username, password));
    }

    /**
     * Executes the given function.
     */
    private AccessTokenResponse execute(Supplier<AccessTokenResponse> supplier)
    {
        try
        {
            AccessTokenResponse tokenResponse = supplier.get();
            // Verify token (if enabled)
            verifyToken(tokenResponse.getToken());

            return tokenResponse;
        }
        catch (HttpResponseException ex)
        {
            if (LOGGER.isDebugEnabled())
            {
                LOGGER.debug("Failed to authenticate user against Keycloak. Status: " + ex.getStatusCode() + " Reason: " + ex.getReasonPhrase());
            }

            throw new AuthenticationException("Failed to authenticate user against Keycloak.", ex);
        }
    }

    /**
     * Verifies token.Typically called after successful tokenResponse is received from Keycloak.
     *
     * @return the verified and parsed {@code AccessToken} or null
     * if the {@literal validate-token} property is set to false.
     */
    public AccessToken verifyToken(String tokenStr)
    {
        if (config.isValidateToken())
        {
            try
            {
                return AdapterTokenVerifier.verifyToken(tokenStr, deployment);
            }
            catch (VerificationException ex)
            {
                throw new AuthenticationException("Failed token verification.", ex);
            }
        }
        return null;
    }
}
