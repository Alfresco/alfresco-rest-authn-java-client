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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.alfresco.rest.authn.config.IdentityServiceConfig;
import org.alfresco.rest.authn.config.PropertiesHelper;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Test;

import org.springframework.core.env.Environment;

/**
 * @author Jamal Kaabi-Mofrad
 */
public class PropertyConfigTest
{
    private Set<String> systemPropertiesKeys = new HashSet<>();

    @After
    public void tearDown()
    {
        // Clean up the added system properties
        systemPropertiesKeys.forEach(System::clearProperty);
        systemPropertiesKeys.clear();
    }

    @Test
    public void testDefaultProperties()
    {
        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder().build();
        IdentityServiceConfig config = authnConfigBuilder.getIdentityServiceConfig();

        assertEquals(getServerAuthUrl("http://localhost:8080/auth"), config.getAuthServerUrl());
        assertEquals("alfresco", config.getRealm());
        assertEquals("external", config.getSslRequired());
        assertEquals("alfresco", config.getResource());
        assertTrue(config.isPublicClient());
        assertTrue(config.isValidateToken());
        assertEquals("password", config.getGrantType());
        assertEquals("admin", config.getUsername());
        assertEquals("admin", config.getPassword());
        assertEquals(2000, config.getClientConnectionTimeoutInMillis());
        assertEquals(2000, config.getClientSocketTimeoutInMillis());
        assertTrue(config.getCredentialsSecret().isEmpty());
        assertNull(config.getCredentialsProvider());
        //check the setCredentials method
        config.setCredentials();
        Map<String, Object> credentials = config.getCredentials();
        assertNotNull(credentials);
        assertEquals("", credentials.get("secret"));
        assertNull(credentials.get("provider"));

        // Check other properties
        checkOtherProperties(config);
    }

    @Test
    public void testOverrideWithProperties()
    {
        Properties properties = new Properties();
        properties.setProperty("alfresco.identity.service.auth-server-url", "http://localhost-test:9090/auth");
        properties.setProperty("alfresco.identity.service.ssl-required", "none");
        properties.setProperty("alfresco.identity.service.public-client", Boolean.FALSE.toString());
        properties.setProperty("alfresco.identity.service.username", "testUser");
        properties.setProperty("alfresco.identity.service.password", "testPassword");
        properties.setProperty("alfresco.identity.service.credentials-secret", "testSecret");
        properties.setProperty("alfresco.identity.service.credentials-provider", "test-provider");

        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(properties).build();
        IdentityServiceConfig config = authnConfigBuilder.getIdentityServiceConfig();

        assertEquals(getServerAuthUrl("http://localhost-test:9090/auth"), config.getAuthServerUrl());
        assertEquals("alfresco", config.getRealm());
        assertEquals("none", config.getSslRequired());
        assertFalse(config.isPublicClient());
        assertEquals("testUser", config.getUsername());
        assertEquals("testPassword", config.getPassword());
        assertEquals("testSecret", config.getCredentialsSecret());
        assertEquals("test-provider", config.getCredentialsProvider());

        //check the setCredentials method
        config.setCredentials();
        Map<String, Object> credentials = config.getCredentials();
        assertNotNull(credentials);
        assertEquals("testSecret", credentials.get("secret"));
        assertEquals("test-provider", credentials.get("provider"));

        // Check other properties. They should have the default values
        checkOtherProperties(config);
    }

    @Test
    public void testOverrideWithSpringEnv()
    {
        Environment environment = mock(Environment.class);
        when(environment.getProperty("alfresco.identity.service.auth-server-url")).thenReturn("http://localhost-spring:9090/auth");
        when(environment.containsProperty("alfresco.identity.service.auth-server-url")).thenReturn(true);

        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(environment).build();
        IdentityServiceConfig config = authnConfigBuilder.getIdentityServiceConfig();

        assertEquals("http://localhost-spring:9090/auth", config.getAuthServerUrl());

        // Check other properties. They should have the default values
        checkOtherProperties(config);
    }

    @Test
    public void testOverridePropertiesWithSystemProperties()
    {
        // Set System properties to simulate the given command line properties
        setSystemProperty("ALFRESCO_IDENTITY_SERVICE_VALIDATE_TOKEN", "false");
        setSystemProperty("ALFRESCO_IDENTITY_SERVICE_USERNAME", "testUsername");
        setSystemProperty("ALFRESCO_IDENTITY_SERVICE_CREDENTIALS_SECRET", "testSecret");
        setSystemProperty("alfresco.identity.service.password", "testPassword");

        Properties properties = new Properties();
        properties.setProperty("alfresco.identity.service.username", "john.doe");
        properties.setProperty("alfresco.identity.service.password", "john-password");

        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(properties).build();
        IdentityServiceConfig config = authnConfigBuilder.getIdentityServiceConfig();

        assertFalse("System property should have overridden the default property.", config.isValidateToken());
        assertEquals("System property should have overridden the default property.", "testSecret", config.getCredentialsSecret());
        assertEquals("System property should have overridden the supplied property.", "testPassword", config.getPassword());
        assertEquals("System property should have overridden the supplied property.", "testUsername", config.getUsername());

        // Check other properties. They should have the default values
        checkOtherProperties(config);
    }

    @Test
    public void testOverridePropertiesWithK8Secret() throws Exception
    {
        File parentDir = createTempDir();
        File secret = new File(parentDir, "secret");
        File password = new File(parentDir, "password");

        FileUtils.writeStringToFile(secret, "test-via-k8-secret", StandardCharsets.UTF_8.toString());
        FileUtils.writeStringToFile(password, "test-via-k8-password", StandardCharsets.UTF_8.toString());

        // Set secret via system property
        setSystemProperty("alfresco.identity.service.credentials-secret", "testSecret");

        //Set password via properties object
        Properties properties = new Properties();
        properties.setProperty("alfresco.identity.service.password", "john-password");

        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(properties)
                    .withK8Secret(parentDir.getPath())
                    .build();
        IdentityServiceConfig config = authnConfigBuilder.getIdentityServiceConfig();

        assertEquals("K8 secret should have overridden any property.", "test-via-k8-secret", config.getCredentialsSecret());
        assertEquals("K8 secret should have overridden any property.", "test-via-k8-password", config.getPassword());

        // cleanup
        FileUtils.deleteDirectory(parentDir);
    }

    @Test
    public void testOverrideWithPropertiesHelper()
    {
        PropertiesHelper helper = new PropertiesHelper();
        helper.setAuthServerUrl("http://localhost-helper:9999/auth")
                    .setUsername("helper-test-username")
                    .setPassword("helper-test-password")
                    .setClientConnectionTimeoutInMillis(4000)
                    .setClientSocketTimeoutInMillis(5000)
                    .setCredentialsSecret("helper-test-secret")
                    .setCredentialsProvider("helper-test-provider")
                    .setRealm("helper-test-realm")
                    .setResource("helper-test-resource")
                    .setPublicClient(false)
                    .setValidateToken(false);

        AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(helper.getProperties()).build();
        IdentityServiceConfig config = authnConfigBuilder.getIdentityServiceConfig();

        assertEquals(getServerAuthUrl("http://localhost-helper:9999/auth"), config.getAuthServerUrl());
        assertEquals("helper-test-realm", config.getRealm());
        assertEquals("helper-test-resource", config.getResource());
        assertEquals("helper-test-username", config.getUsername());
        assertEquals("helper-test-password", config.getPassword());
        assertEquals("helper-test-secret", config.getCredentialsSecret());
        assertEquals("helper-test-provider", config.getCredentialsProvider());
        assertEquals(4000, config.getClientConnectionTimeoutInMillis());
        assertEquals(5000, config.getClientSocketTimeoutInMillis());
        assertFalse(config.isPublicClient());
        assertFalse(config.isValidateToken());

        //check the setCredentials method
        config.setCredentials();
        Map<String, Object> credentials = config.getCredentials();
        assertNotNull(credentials);
        assertEquals("helper-test-secret", credentials.get("secret"));
        assertEquals("helper-test-provider", credentials.get("provider"));

        // Check other properties. They should have the default values
        checkOtherProperties(config);
    }

    private void setSystemProperty(String key, String value)
    {
        systemPropertiesKeys.add(key);
        System.setProperty(key, value);
    }

    private String getServerAuthUrl(String defaultValue)
    {
        // Get the url as we might override that via command line or in the build system.
        return System.getProperty("alfresco.identity.service.auth-server-url", defaultValue);
    }

    private File createTempDir()
    {
        File temp = new File(FileUtils.getTempDirectory(), "authnTest"+System.currentTimeMillis());
        assertTrue(temp.mkdir());
        return temp;
    }

    private void checkOtherProperties(IdentityServiceConfig config)
    {
        assertFalse(config.isVerifyTokenAudience());
        assertNull(config.getRealmKey());
        assertEquals(0, config.getConfidentialPort());
        assertFalse(config.isUseResourceRoleMappings());
        assertFalse(config.isCors());
        assertEquals(-1, config.getCorsMaxAge());
        assertNull(config.getCorsAllowedHeaders());
        assertNull(config.getCorsAllowedMethods());
        assertNull(config.getCorsExposedHeaders());
        assertFalse(config.isExposeToken());
        assertFalse(config.isBearerOnly());
        assertFalse(config.isAutodetectBearerOnly());
        assertFalse(config.isEnableBasicAuth());
        assertFalse(config.isAllowAnyHostname());
        assertFalse(config.isDisableTrustManager());
        assertNull(config.getTruststore());
        assertNull(config.getTruststorePassword());
        assertNull(config.getClientKeystore());
        assertNull(config.getClientKeystorePassword());
        assertNull(config.getClientKeyPassword());
        assertEquals(20, config.getConnectionPoolSize());
        assertFalse(config.isAlwaysRefreshToken());
        assertFalse(config.isRegisterNodeAtStartup());
        assertEquals(-1, config.getRegisterNodePeriod());
        assertNull(config.getTokenStore());
        assertNull(config.getPrincipalAttribute());
        assertNull(config.getTurnOffChangeSessionIdOnLogin());
        assertEquals(0, config.getTokenMinimumTimeToLive());
        assertEquals(10, config.getMinTimeBetweenJwksRequests());
        assertEquals(86400, config.getPublicKeyCacheTtl());
        assertFalse(config.isPkce());
        assertFalse(config.isIgnoreOAuthQueryParameter());
    }
}
