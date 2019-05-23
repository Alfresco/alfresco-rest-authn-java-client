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
package org.alfresco.rest.authn.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.keycloak.representations.adapters.config.AdapterConfig;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Identity service configuration properties.
 *
 * @author Jamal Kaabi-Mofrad
 */
public class IdentityServiceConfig extends AdapterConfig
{
    @JsonProperty("grant-type")
    private String grantType;

    @JsonProperty("username")
    private String username;

    @JsonProperty("password")
    private String password;

    @JsonProperty("credentials-secret")
    private String credentialsSecret;

    @JsonProperty("credentials-provider")
    private String credentialsProvider;

    @JsonProperty("validate-token")
    private boolean validateToken;

    @JsonProperty("client-connection-timeout")
    private int clientConnectionTimeoutInMillis;

    @JsonProperty("client-socket-timeout")
    private int clientSocketTimeoutInMillis;

    public String getGrantType()
    {
        return grantType;
    }

    public void setGrantType(String grantType)
    {
        this.grantType = grantType;
    }

    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getPassword()
    {
        return password;
    }

    public void setPassword(String password)
    {
        this.password = password;
    }

    public String getCredentialsSecret()
    {
        return credentialsSecret;
    }

    public void setCredentialsSecret(String credentialsSecret)
    {
        this.credentialsSecret = credentialsSecret;
    }

    public String getCredentialsProvider()
    {
        return credentialsProvider;
    }

    public void setCredentialsProvider(String credentialsProvider)
    {
        this.credentialsProvider = credentialsProvider;
    }

    public boolean isValidateToken()
    {
        return validateToken;
    }

    public void setValidateToken(boolean validateToken)
    {
        this.validateToken = validateToken;
    }

    public int getClientConnectionTimeoutInMillis()
    {
        return clientConnectionTimeoutInMillis;
    }

    public void setClientConnectionTimeoutInMillis(int clientConnectionTimeoutInMillis)
    {
        this.clientConnectionTimeoutInMillis = clientConnectionTimeoutInMillis;
    }

    public int getClientSocketTimeoutInMillis()
    {
        return clientSocketTimeoutInMillis;
    }

    public void setClientSocketTimeoutInMillis(int clientSocketTimeoutInMillis)
    {
        this.clientSocketTimeoutInMillis = clientSocketTimeoutInMillis;
    }

    /**
     * Helper method to set the credentials.
     */
    @JsonIgnore
    public void setCredentials()
    {
        Map<String, Object> credentials = new LinkedHashMap<>(2);
        if (credentialsSecret != null)
        {
            credentials.put("secret", credentialsSecret);
        }

        if (credentialsProvider != null)
        {
            credentials.put("provider", credentialsProvider);
        }

        if (!credentials.isEmpty())
        {
            setCredentials(credentials);
        }
    }
}
