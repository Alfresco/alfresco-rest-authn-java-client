## Alfresco REST Authentication Java Client

Alfresco REST Authentication Java Client is a library that can be used to obtain a JWT access token from the Keycloak Server.

### Building and testing
The project can be built by running Maven command:
~~~
mvn clean install
~~~
The integration tests require the appropriate properties. At minimum, you need to provide the Keycloak Auth Server URL. For example:
~~~
mvn clean install -Dit-test -Dalfresco.identity.service.auth-server-url=http://localhost:8080/auth
~~~

### Artifacts
The artifacts can be obtained by:
* downloading from [Alfresco repository](https://artifacts.alfresco.com/nexus/content/groups/public)
* getting as Maven dependency by adding the dependency to your pom file:
~~~
<dependency>
  <groupId>org.alfresco</groupId>
  <artifactId>alfresco-rest-authn-java-client</artifactId>
  <version>version</version>
</dependency>
~~~
and Alfresco Maven repository:
~~~
<repository>
  <id>alfresco-maven-repo</id>
  <url>https://artifacts.alfresco.com/nexus/content/groups/public</url>
</repository>
~~~

## Usage Examples

The library will be loaded with a set of default [properties](src/main/resources/authn-config.properties 
) at runtime, therefore, you will need to provide at minimum the Keycloak auth server URL and depending on the grant_type, username/password or a client secret.


### Setting the required properties in pure Java (no Spring)

```java
    PropertiesHelper helper = new PropertiesHelper();
    helper.setAuthServerUrl("http://localhost:8080/auth")
             .setUsername("username")
             .setPassword("password");

    AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(helper.getProperties()).build();
    TokenProvider tokenProvider = new TokenProvider(authnConfigBuilder);

    AccessTokenResponse tokenResponse = tokenProvider.getAccessToken();
    tokenResponse.getToken();
```

Or you can ignore setting the username and password as the above example and then provide the username/password at the invocation time:

```java
    PropertiesHelper helper = new PropertiesHelper();
    helper.setAuthServerUrl("http://localhost:8080/auth")

    AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(helper.getProperties()).build();
    TokenProvider tokenProvider = new TokenProvider(authnConfigBuilder);
    
    AccessTokenResponse tokenResponse = tokenProvider.getAccessToken("username", "password");
    tokenResponse.getToken();
```

**Note**: All the available [properties](src/main/resources/authn-config.properties) can be overridden by the System/Environment properties.
Also, note that System/Environment properties take precedence over the *Properties* object that is passed to the *AuthnConfigBuilder.Builder* class.

### Setting the required properties in Spring

Assuming that you have overridden the required properties in your **_application.properties_** file, for example,

```properties
alfresco.identity.service.grant-type=client_credentials
alfresco.identity.service.credentials-secret=e89126c6-ae4f-4a1d-ad9b-260d626bfe89
```

you can obtain the Spring *Environment* object and then pass it to builder class to override the default values.

```java
    @Autowired
    private Environment environment;

    AuthnConfigBuilder authnConfigBuilder = new AuthnConfigBuilder.Builder(environment).build();
    TokenProvider tokenProvider = new TokenProvider(authnConfigBuilder);

    AccessTokenResponse tokenResponse = tokenProvider.getAccessToken();
    tokenResponse.getToken();

``` 
