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

import java.util.Properties;

/**
 * A helper class to create a {@link Properties} object with
 * a set of usually used Identity Service configurations.
 * <p>
 * The created {@code Properties} object then needs be passed to
 * the {@link org.alfresco.rest.authn.AuthnConfigBuilder.Builder} object
 * to override the default values.
 *
 * @author Jamal Kaabi-Mofrad
 */
public class PropertiesHelper
{
    private Properties properties;

    public PropertiesHelper()
    {
        this.properties = new Properties();
    }

    public Properties getProperties()
    {
        return properties;
    }

    public PropertiesHelper setAuthServerUrl(String authServerUrl)
    {
        properties.setProperty("alfresco.identity.service.auth-server-url", authServerUrl);
        return this;
    }

    public PropertiesHelper setRealm(String realm)
    {
        properties.setProperty("alfresco.identity.service.realm", realm);
        return this;
    }

    public PropertiesHelper setSslRequired(String sslRequired)
    {
        properties.setProperty("alfresco.identity.service.ssl-required", sslRequired);
        return this;
    }

    public PropertiesHelper setResource(String resource)
    {
        properties.setProperty("alfresco.identity.service.resource", resource);
        return this;
    }

    public PropertiesHelper setGrantType(String grantType)
    {
        properties.setProperty("alfresco.identity.service.grant-type", grantType);
        return this;
    }

    public PropertiesHelper setUsername(String username)
    {
        properties.setProperty("alfresco.identity.service.username", username);
        return this;
    }

    public PropertiesHelper setPassword(String password)
    {
        properties.setProperty("alfresco.identity.service.password", password);
        return this;
    }

    public PropertiesHelper setCredentialsSecret(String credentialsSecret)
    {
        properties.setProperty("alfresco.identity.service.credentials-secret", credentialsSecret);
        return this;
    }

    public PropertiesHelper setCredentialsProvider(String credentialsProvider)
    {
        properties.setProperty("alfresco.identity.service.credentials-provider", credentialsProvider);
        return this;
    }

    public PropertiesHelper setClientConnectionTimeoutInMillis(int connectionTimeout)
    {
        properties.setProperty("alfresco.identity.service.client-connection-timeout", Integer.toString(connectionTimeout));
        return this;
    }

    public PropertiesHelper setClientSocketTimeoutInMillis(int socketTimeout)
    {
        properties.setProperty("alfresco.identity.service.client-socket-timeout", Integer.toString(socketTimeout));
        return this;
    }

    public PropertiesHelper setPublicClient(boolean publicClient)
    {
        properties.setProperty("alfresco.identity.service.public-client", Boolean.toString(publicClient));
        return this;
    }

    public PropertiesHelper setValidateToken(boolean validateToken)
    {
        properties.setProperty("alfresco.identity.service.validate-token", Boolean.toString(validateToken));
        return this;
    }

    public PropertiesHelper setVerifyTokenAudience(boolean verifyTokenAudience)
    {
        properties.setProperty("alfresco.identity.service.verify-token-audience", Boolean.toString(verifyTokenAudience));
        return this;
    }
}
