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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.alfresco.rest.authn.config.IdentityServiceConfig;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOCase;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.jboss.logging.Logger;
import org.keycloak.util.SystemPropertiesJsonParserFactory;
import org.springframework.core.env.Environment;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Identity service configuration builder.
 *
 * @author Jamal Kaabi-Mofrad
 */
public class AuthnConfigBuilder
{
    private static final Logger LOGGER = Logger.getLogger(AuthnConfigBuilder.class);

    private static final NameFileFilter NAME_FILE_FILTER = new NameFileFilter(AuthnInfoK8Secret.getFileNames(), IOCase.SENSITIVE);
    private static final String CONFIG_KEY_PREFIX = "alfresco.identity.service.";
    private static final String ENV_KEY_PREFIX = "ALFRESCO_IDENTITY_SERVICE_";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(new SystemPropertiesJsonParserFactory());

    static
    {
        OBJECT_MAPPER.setSerializationInclusion(Include.NON_DEFAULT);
    }

    private final IdentityServiceConfig identityServiceConfig;

    private AuthnConfigBuilder(Builder builder)
    {
        // Construct the config POJO from properties
        String json = toJsonAsString(builder.defaultProperties);
        this.identityServiceConfig = convertToIdentityServiceConfig(json);

        // Override the protected details with k8 secret
        Collection<File> files = builder.k8SecretFiles;
        if (files != null && !files.isEmpty())
        {
            files.forEach(file -> {
                AuthnInfoK8Secret configInfo = AuthnInfoK8Secret.lookupByFileName(file.getName());
                String value = readFileAsString(file);
                if (value != null && !value.isEmpty())
                {
                    configInfo.setBuilderValue(identityServiceConfig, value);
                }
            });
        }

        // Now that we have resolved the properties, set the credentials
        this.identityServiceConfig.setCredentials();

        if(LOGGER.isInfoEnabled())
        {
            LOGGER.info("Identity Service Configuration:");
            LOGGER.info("    Authentication Server url: " + this.identityServiceConfig.getAuthServerUrl());
            LOGGER.info("    grant_type: " + this.identityServiceConfig.getGrantType());
            LOGGER.info("    validate token: " + this.identityServiceConfig.isValidateToken());
        }
    }

    /**
     * Gets the {@code IdentityServiceConfig} object created after the properties have been resolved.
     */
    public IdentityServiceConfig getIdentityServiceConfig()
    {
        return identityServiceConfig;
    }

    /**
     * Converts the JSON String into {@code IdentityServiceConfig} object.
     */
    private static IdentityServiceConfig convertToIdentityServiceConfig(String jsonStr)
    {
        try
        {
            return OBJECT_MAPPER.readValue(jsonStr, IdentityServiceConfig.class);
        }
        catch (IOException ex)
        {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Converts the properties config into a JSON String
     */
    private static String toJsonAsString(final Map<String, String> properties)
    {
        Map<String, String> sanitizeProperties = new HashMap<>();

        properties.entrySet()
                    .stream()
                    .filter(entry -> entry.getKey().startsWith(CONFIG_KEY_PREFIX))
                    .forEach(entry -> sanitizeProperties.put(entry.getKey().substring(CONFIG_KEY_PREFIX.length()), entry.getValue()));

        try
        {
            return OBJECT_MAPPER.writeValueAsString(sanitizeProperties);
        }
        catch (JsonProcessingException ex)
        {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Reads the contents of a file into a String.
     */
    private static String readFileAsString(File file)
    {
        try
        {
            return FileUtils.readFileToString(file, StandardCharsets.UTF_8);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * A builder class that creates an instance of {@link AuthnConfigBuilder} class.
     */
    public static class Builder
    {
        private final Map<String, String> defaultProperties;
        private Collection<File> k8SecretFiles;

        public Builder()
        {
            this.defaultProperties = loadDefaultPropertiesAsMap();

            // Override with System properties
            overrideWithSystemProperties();
        }

        public Builder(Properties properties)
        {
            this.defaultProperties = loadDefaultPropertiesAsMap();

            Set<String> defaultKeys = defaultProperties.keySet();
            // Override the default values if only the key exists in the given properties
            defaultKeys.stream().filter(properties::containsKey).forEach(k -> defaultProperties.put(k, properties.getProperty(k)));

            // Override with System properties
            overrideWithSystemProperties();
        }

        public Builder(Environment environment)
        {
            this.defaultProperties = loadDefaultPropertiesAsMap();

            Set<String> defaultKeys = defaultProperties.keySet();
            // Override the default values if only the key exists in the given environment
            defaultKeys.stream().filter(environment::containsProperty).forEach(k -> defaultProperties.put(k, environment.getProperty(k)));

            // Spring Environment is already taking care of the System/Env properties.
        }

        public Builder withK8Secret(String k8SecretDirPath)
        {
            File parent = new File(k8SecretDirPath);
            if (parent.exists() && parent.isDirectory())
            {
                this.k8SecretFiles = FileUtils.listFiles(parent, NAME_FILE_FILTER, null);
            }
            return this;
        }

        private Map<String, String> loadDefaultPropertiesAsMap()
        {
            Properties properties = new Properties();
            try (InputStream inputStream = AuthnConfigBuilder.class.getClassLoader().getResourceAsStream("authn-config.properties"))
            {
                properties.load(inputStream);
            }
            catch (IOException ex)
            {
                throw new RuntimeException("Couldn't load the properties file.", ex);
            }

            Map<String, String> map = new HashMap<>(properties.size());
            properties.forEach((key, value) -> map.put(key.toString(), getValueOrNull(value.toString())));
            return map;
        }

        private String getValueOrNull(String value)
        {
            return ("null".equals(value) ? null : value);
        }

        private void overrideWithSystemProperties()
        {
            Properties props = System.getProperties();
            // Sanitise the keys
            Map<String, String> map = props.entrySet()
                        .stream()
                        .filter(entry -> isIdentityServiceProperty(entry.getKey().toString()))
                        .collect(Collectors.toMap(entry -> convertKey(entry.getKey().toString()), entry -> entry.getValue().toString()));

            // Override with System properties
            Set<String> defaultKeys = defaultProperties.keySet();
            // Override the default values if only the key exists in the system properties
            defaultKeys.stream().filter(map::containsKey).forEach(k -> defaultProperties.put(k, map.get(k)));
        }

        private boolean isIdentityServiceProperty(String key)
        {
            return (key.startsWith(ENV_KEY_PREFIX) || key.startsWith(CONFIG_KEY_PREFIX));
        }

        private String convertKey(String key)
        {
            return key.toLowerCase().replace("_", ".");
        }

        public AuthnConfigBuilder build()
        {
            return new AuthnConfigBuilder(this);
        }
    }

    /**
     * Represents the supported K8 secret files.
     */
    public enum AuthnInfoK8Secret
    {
        CLIENT_SECRET("secret")
        {
            @Override
            public void setBuilderValue(IdentityServiceConfig config, String value)
            {
                config.setCredentialsSecret(value);
            }
        },
        USERNAME("username")
        {
            @Override
            public void setBuilderValue(IdentityServiceConfig config, String value)
            {
                config.setUsername(value);
            }
        },
        PASSWORD("password")
        {
            @Override
            public void setBuilderValue(IdentityServiceConfig config, String value)
            {
                config.setPassword(value);
            }
        };

        private static final Map<String, AuthnInfoK8Secret> FILE_NAME_LOOKUP = new HashMap<>(3);

        static
        {
            for (AuthnInfoK8Secret info : values())
            {
                FILE_NAME_LOOKUP.put(info.fileName, info);
            }
        }

        private final String fileName;

        AuthnInfoK8Secret(String fileName)
        {
            this.fileName = fileName;
        }

        public static AuthnInfoK8Secret lookupByFileName(String fileName)
        {
            return FILE_NAME_LOOKUP.get(fileName);
        }

        public static List<String> getFileNames()
        {
            return Stream.of(values()).map(AuthnInfoK8Secret::getFileName).collect(Collectors.toList());
        }

        public String getFileName()
        {
            return this.fileName;
        }

        public abstract void setBuilderValue(IdentityServiceConfig config, String value);
    }
}

