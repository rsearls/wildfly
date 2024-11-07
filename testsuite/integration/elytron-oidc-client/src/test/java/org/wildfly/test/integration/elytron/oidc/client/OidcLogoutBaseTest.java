/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SYSTEM_PROPERTY;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.VALUE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.ClientAppType;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.test.http.util.TestHttpClientUtils;
import org.jboss.as.test.integration.management.ManagementOperations;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.as.test.shared.ManagementServerSetupTask;
import org.jboss.as.test.shared.TestSuiteEnvironment;
import org.jboss.as.test.shared.util.AssumeTestGroupUtil;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.wildfly.security.jose.util.JsonSerialization;
import org.wildfly.test.integration.elytron.oidc.client.deployment.OidcWithDeploymentConfigTest;

import io.restassured.RestAssured;

/**
 * Tests for the OpenID Connect authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public abstract class OidcLogoutBaseTest {

    public static final String CLIENT_SECRET = "longerclientsecretthatisstleast256bitslong";
    public static final String OIDC_WITHOUT_SUBSYSTEM_CONFIG_WEB_XML = "web.xml";
    public static KeycloakContainer KEYCLOAK_CONTAINER;
    public static final String TEST_REALM = "WildFly";
    private static final String KEYCLOAK_USERNAME = "username";
    private static final String KEYCLOAK_PASSWORD = "password";
    public static final int CLIENT_PORT = TestSuiteEnvironment.getHttpPort();
    public static final String CLIENT_HOST_NAME = TestSuiteEnvironment.getHttpAddress();
    public static final String PROVIDER_URL_APP = "ProviderUrlOidcApp";
    public static final String AUTH_SERVER_URL_APP = "AuthServerUrlOidcApp";
    public static final String REST_AUTH_SERVER_URL_APP = "RestAuthServerUrlOidcApp";
    public static final String WRONG_PROVIDER_URL_APP = "WrongProviderUrlOidcApp";
    public static final String WRONG_SECRET_APP = "WrongSecretOidcApp";
    public static final String FORM_WITH_OIDC_EAR_APP = "FormWithOidcApp";
    public static final String FORM_WITH_OIDC_OIDC_APP = "oidc";
    public static final String DIRECT_ACCCESS_GRANT_ENABLED_CLIENT = "DirectAccessGrantEnabledClient";
    public static final String BEARER_ONLY_AUTH_SERVER_URL_APP = "AuthServerUrlBearerOnlyApp";
    public static final String BEARER_ONLY_PROVIDER_URL_APP = "ProviderUrlBearerOnlyApp";
    public static final String BASIC_AUTH_PROVIDER_URL_APP = "BasicAuthProviderUrlApp";
    public static final String CORS_PROVIDER_URL_APP = "CorsApp";
    private static final String WRONG_PASSWORD = "WRONG_PASSWORD";
    private static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    private static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    private static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
    private static final String ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
    static final String ORIGIN = "Origin";
    static final String ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";
    static final String ACCESS_CONTROL_REQUEST_HEADERS = "Access-Control-Request-Headers";
    public static final String CORS_CLIENT = "CorsClient";
    public static final String OPENID_SCOPE_APP = "OpenIDScopeApp";
    public static final String INVALID_SCOPE_APP = "InvalidScopeApp";
    public static final String SINGLE_SCOPE_APP = "SingleScopeApp";
    public static final String MULTIPLE_SCOPE_APP = "MultipleScopeApp";
    public static final String OAUTH2_REQUEST_METHOD_APP = "OAuth2RequestApp";
    public static final String PLAINTEXT_REQUEST_APP = "PlainTextRequestApp";
    public static final String PLAINTEXT_REQUEST_URI_APP = "PlainTextRequestUriApp";
    public static final String PLAINTEXT_ENCRYPTED_REQUEST_APP = "PlainTextEncryptedRequestApp";
    public static final String PLAINTEXT_ENCRYPTED_REQUEST_URI_APP = "PlainTextEncryptedRequestUriApp";
    public static final String RSA_SIGNED_REQUEST_APP = "RsaSignedRequestApp";
    public static final String RSA_SIGNED_AND_ENCRYPTED_REQUEST_APP = "RSASignedAndEncryptedRequestApp";
    public static final String SIGNED_AND_ENCRYPTED_REQUEST_URI_APP = "SignedAndEncryptedRequestUriApp";
    public static final String PS_SIGNED_RSA_ENCRYPTED_REQUEST_APP = "PsSignedAndRsaEncryptedRequestApp";
    public static final String INVALID_SIGNATURE_ALGORITHM_APP = "InvalidSignatureAlgorithmApp";
    public static final String PS_SIGNED_REQUEST_URI_APP = "PsSignedRequestUriApp";
    public static final String MISSING_SECRET_APP = "MissingSecretApp";
    public static final String FORM_USER="user1";
    public static final String FORM_PASSWORD="password1";
    protected static final String ERROR_PAGE_CONTENT = "Error!";

    // Avoid problem on windows with path
    public static final String USERS_PATH = new File(
            OidcWithDeploymentConfigTest.class.getResource("users.properties").getFile()).getAbsolutePath()
            .replace("\\", "/");
    public static final String ROLES_PATH = new File(
            OidcWithDeploymentConfigTest.class.getResource("roles.properties").getFile()).getAbsolutePath()
            .replace("\\", "/");
    public static final String ORIGINAL_USERS_PATH = "application-users.properties";
    public static final String ORIGINAL_ROLES_PATH = "application-roles.properties";
    public static final String RELATIVE_TO = "jboss.server.config.dir";

    // FRONTCHANNEL_LOGOUT_PATH
    private static final String RP_INITIATED_LOGOUT_PATH = "/logout";
    private static final String BACKCHANNEL_LOGOUT_PATH = RP_INITIATED_LOGOUT_PATH;
    private static final String FRONTCHANNEL_LOGOUT_PATH = "/frontLogout";
    //private static final String FRONTCHANNEL_LOGOUT_PATH = "/logout/callback";

    private final Stability desiredStability;

    public OidcLogoutBaseTest(Stability desiredStability) {
        this.desiredStability = desiredStability;
    }

    private enum BearerAuthType {
        BEARER,
        QUERY_PARAM,
        BASIC
    }

    public enum LogoutChannel {
        RP_INITIATED,
        FRONTCHANNEL,
        BACKCHANNEL,
        BACKCHANNEL_NO_ENDPOINT
    }

    private enum RestMethod {
        GET,
        POST
    }

    public static void sendRealmCreationRequest(RealmRepresentation realm) {
        try {
            String adminAccessToken = KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl());
            assertNotNull(adminAccessToken);
            RestAssured
                    .given()
                    .auth().oauth2(adminAccessToken)
                    .contentType("application/json")
                    .body(JsonSerialization.writeValueAsBytes(realm))
                    .when()
                    .post(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms").then()
                    .statusCode(201);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // provide config for frontchannel, backchannel OIDC logout
    public static void setupOidcLogout(RealmRepresentation realm,
                                       Map<String, ClientAppType> clientApps,
                                       Map<String, LogoutChannel> appLogout) {

        for (ClientRepresentation client : realm.getClients()) {
            ClientAppType value = clientApps.get(client.getClientId());
            if (value == ClientAppType.OIDC_CLIENT) {
                /* rls these may not be needed
                realm.setAccessTokenLifespan(100);
                realm.setSsoSessionMaxLifespan(100);
                */
                List<String> redirectUris = new ArrayList<>(client.getRedirectUris());
                String redirectUri = redirectUris.get(0);
                redirectUris.add("*");
                client.setRedirectUris(redirectUris);

                if(client.getAttributes() == null) {
                    client.setAttributes(new HashMap<>());
                }

                LogoutChannel lChannel = appLogout.get(client.getClientId());
                if (lChannel != null) {

                    String tmpRedirectUri = redirectUri;
                    int indx = redirectUri.lastIndexOf("/*");
                    if (indx > -1) {
                        tmpRedirectUri = redirectUri.substring(0,indx);
                    }

                    switch(lChannel) {
                        case FRONTCHANNEL:
                            client.setFrontchannelLogout(true);
                            client.getAttributes().put("frontchannel.logout.url",
                                    tmpRedirectUri + FRONTCHANNEL_LOGOUT_PATH);
                            redirectUris.add(tmpRedirectUri + FRONTCHANNEL_LOGOUT_PATH);
                            break;
                        case RP_INITIATED:
                            redirectUris.add(tmpRedirectUri + BACKCHANNEL_LOGOUT_PATH);
                            break;
                        case BACKCHANNEL:
                            client.setFrontchannelLogout(false);
                            client.getAttributes().put("backchannel.logout.session.required", "true");
                            client.getAttributes().put("backchannel.logout.url",
                                    tmpRedirectUri + BACKCHANNEL_LOGOUT_PATH);
                            redirectUris.add(tmpRedirectUri + BACKCHANNEL_LOGOUT_PATH);
                            break;
                        case BACKCHANNEL_NO_ENDPOINT:
                            client.setFrontchannelLogout(false);
                            break;
                    }
                }
            }
        }
    }

    @BeforeClass
    public static void checkDockerAvailability() {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", AssumeTestGroupUtil.isDockerAvailable());
    }

    protected static String getClientUrl(String clientApp) {
        return "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/" + clientApp;
    }


    @Test
    @OperateOnDeployment(REST_AUTH_SERVER_URL_APP)
    public void testOidcLogout() throws Exception {

        loginToApp(REST_AUTH_SERVER_URL_APP,
                org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.ALICE,
                org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.ALICE_PASSWORD,
                HttpURLConnection.HTTP_OK, SimpleServlet.RESPONSE_BODY);

        URI requestUri = new URL("http", TestSuiteEnvironment.getHttpAddress(), TestSuiteEnvironment.getHttpPort(),
                "/" + REST_AUTH_SERVER_URL_APP + SimpleSecuredServlet.SERVLET_PATH + RP_INITIATED_LOGOUT_PATH).toURI();

        // rls logoutOfKeycloak(requestUri, RestMethod.POST, HttpURLConnection.HTTP_OK, "success", true);
        logoutOfKeycloak(requestUri, RestMethod.GET, HttpURLConnection.HTTP_OK, "success", true);

    }

    /*------------------ rls start
        @Test
        @OperateOnDeployment(AUTH_SERVER_URL_APP)
        public void testWrongRoleWithAuthServerUrl() throws Exception {
            loginToApp(AUTH_SERVER_URL_APP, org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.BOB, org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.BOB_PASSWORD, HttpURLConnection.HTTP_FORBIDDEN, null);
        }
        -------------------- rls end */

    public static void loginToApp(String appName, String username, String password, int expectedStatusCode, String expectedText) throws Exception {
        loginToApp(username, password, expectedStatusCode, expectedText, true,
                new URL("http", TestSuiteEnvironment.getHttpAddress(), TestSuiteEnvironment.getHttpPort(),
                "/" + appName + SimpleSecuredServlet.SERVLET_PATH).toURI());
    }

    public static void loginToApp(String appName, String username, String password, int expectedStatusCode, String expectedText, URI requestUri) throws Exception {
        loginToApp(username, password, expectedStatusCode, expectedText, true, requestUri);
    }

    public static void loginToApp(String appName, String username, String password, int expectedStatusCode, String expectedText, boolean loginToKeycloak) throws Exception {
        loginToApp(username, password, expectedStatusCode, expectedText, loginToKeycloak, new URL("http", TestSuiteEnvironment.getHttpAddress(), TestSuiteEnvironment.getHttpPort(),
                "/" + appName + SimpleSecuredServlet.SERVLET_PATH).toURI());
    }

    public static void loginToApp(String username, String password, int expectedStatusCode, String expectedText, boolean loginToKeycloak, URI requestUri) throws Exception {
        loginToApp(username, password, expectedStatusCode, expectedText, loginToKeycloak, requestUri, null, false);
    }

    public static void loginToApp(String username, String password, int expectedStatusCode, String expectedText, boolean loginToKeycloak, URI requestUri, String expectedScope, boolean checkInvalidScope) throws Exception {
        loginToApp(username, password, expectedStatusCode, expectedText, loginToKeycloak, requestUri, expectedScope, checkInvalidScope, null);
    }

    public static void loginToApp(String username, String password, int expectedStatusCode, String expectedText, boolean loginToKeycloak, URI requestUri, String expectedScope, boolean checkInvalidScope, String requestMethod) throws Exception {
        CookieStore store = new BasicCookieStore();
        HttpClient httpClient = TestHttpClientUtils.promiscuousCookieHttpClientBuilder()
                .setDefaultCookieStore(store)
                .setRedirectStrategy(new LaxRedirectStrategy())
                .build();
        HttpGet getMethod = new HttpGet(requestUri);
        HttpContext context = new BasicHttpContext();
        HttpResponse response = httpClient.execute(getMethod, context);
        try {
            int statusCode = response.getStatusLine().getStatusCode();
            if (loginToKeycloak) {
                assertTrue("Expected code == OK but got " + statusCode + " for request=" + requestUri, statusCode == HttpURLConnection.HTTP_OK);
                Form keycloakLoginForm = new Form(response);
                HttpResponse afterLoginClickResponse = simulateClickingOnButton(httpClient, keycloakLoginForm, username, password, "Sign In");
                afterLoginClickResponse.getEntity().getContent();
                assertEquals(expectedStatusCode, afterLoginClickResponse.getStatusLine().getStatusCode());
                if (expectedText != null) {
                    String responseString = new BasicResponseHandler().handleResponse(afterLoginClickResponse);
                    assertTrue("Unexpected result " + responseString, responseString.contains(expectedText));
                }
            }
            else {
                assertTrue("Expected code == FORBIDDEN but got " + statusCode + " for request=" + requestUri, statusCode == HttpURLConnection.HTTP_FORBIDDEN);
            }
        } finally {
            HttpClientUtils.closeQuietly(response);
        }
    }

    public static void logoutOfKeycloak(URI requestUri, RestMethod restMethod, int expectedStatusCode, String expectedText,
                                        boolean logoutFromKeycloak) throws Exception {
        CookieStore store = new BasicCookieStore();
        HttpClient httpClient = TestHttpClientUtils.promiscuousCookieHttpClientBuilder()
                .setDefaultCookieStore(store)
                .setRedirectStrategy(new LaxRedirectStrategy())
                .build();


        HttpContext context = new BasicHttpContext();
        HttpResponse response = null;
        switch(restMethod) {
            case POST:
                HttpPost postMethod = new HttpPost(requestUri);
                URI uri = new URIBuilder(postMethod.getURI())
                        .addParameter("logout", "logout")
                        .build();
                postMethod.setURI(uri);
                response = httpClient.execute(postMethod, context);
                break;
            case GET:
                HttpGet getMethod = new HttpGet(requestUri);
                response = httpClient.execute(getMethod, context);
                break;
            default:
        }

        try {
            int statusCode = response.getStatusLine().getStatusCode();
            if (logoutFromKeycloak) {
                assertTrue("Expected code == OK but got " + statusCode + " for request=" + requestUri, statusCode == HttpURLConnection.HTTP_OK);
                Form keycloakLoginForm = new Form(response);

                String formAction = keycloakLoginForm.getAction();
                /* --- rls
                HttpResponse afterLoginClickResponse = simulateClickingOnButton(httpClient, keycloakLoginForm, username, password, "Sign In");
                afterLoginClickResponse.getEntity().getContent();
                assertEquals(expectedStatusCode, afterLoginClickResponse.getStatusLine().getStatusCode());
                if (expectedText != null) {
                    String responseString = new BasicResponseHandler().handleResponse(afterLoginClickResponse);
                    assertTrue("Unexpected result " + responseString, responseString.contains(expectedText));
                }
                ---- */
            }
            else {
                assertTrue("Expected code == FORBIDDEN but got " + statusCode + " for request=" + requestUri, statusCode == HttpURLConnection.HTTP_FORBIDDEN);
            }
        } finally {
            HttpClientUtils.closeQuietly(response);
        }
    }

    public static class KeycloakSetup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            assumeTrue("Docker isn't available, OIDC tests will be skipped", AssumeTestGroupUtil.isDockerAvailable());
            KEYCLOAK_CONTAINER = new KeycloakContainer();
            KEYCLOAK_CONTAINER.start();
        }

        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            if (KEYCLOAK_CONTAINER != null) {
                KEYCLOAK_CONTAINER.stop();
            }
        }
    }

    public static HttpResponse simulateClickingOnButton(HttpClient client, Form form, String username, String password, String buttonValue) throws IOException {
        final URL url = new URL(form.getAction());
        final HttpPost request = new HttpPost(url.toString());
        final List<NameValuePair> params = new LinkedList<>();
        for (Input input : form.getInputFields()) {
            if (input.type == Input.Type.HIDDEN ||
                    (input.type == Input.Type.SUBMIT && input.getValue().equals(buttonValue))) {
                params.add(new BasicNameValuePair(input.getName(), input.getValue()));
            } else if (input.getName().equals(KEYCLOAK_USERNAME)) {
                params.add(new BasicNameValuePair(input.getName(), username));
            } else if (input.getName().equals(KEYCLOAK_PASSWORD)) {
                params.add(new BasicNameValuePair(input.getName(), password));
            }
        }
        request.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
        return client.execute(request);
    }

    public static final class Form {

        static final String
                NAME = "name",
                VALUE = "value",
                INPUT = "input",
                TYPE = "type",
                ACTION = "action",
                FORM = "form";

        final HttpResponse response;
        final String action;
        final List<Input> inputFields = new LinkedList<>();

        public Form(HttpResponse response) throws IOException {
            this.response = response;
            final String responseString = new BasicResponseHandler().handleResponse(response);
            final Document doc = Jsoup.parse(responseString);
            final Element form = doc.select(FORM).first();
            this.action = form.attr(ACTION);
            for (Element input : form.select(INPUT)) {
                Input.Type type = null;
                switch (input.attr(TYPE)) {
                    case "submit":
                        type = Input.Type.SUBMIT;
                        break;
                    case "hidden":
                        type = Input.Type.HIDDEN;
                        break;
                }
                inputFields.add(new Input(input.attr(NAME), input.attr(VALUE), type));
            }
        }

        public String getAction() {
            return action;
        }

        public List<Input> getInputFields() {
            return inputFields;
        }
    }

    private static final class Input {

        final String name, value;
        final Input.Type type;

        public Input(String name, String value, Input.Type type) {
            this.name = name;
            this.value = value;
            this.type = type;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public enum Type {
            HIDDEN, SUBMIT
        }
    }

    protected static <T extends OidcLogoutBaseTest> void addSystemProperty(ManagementClient client, Class<T> clazz) throws Exception {
        ModelNode add = Util.createAddOperation(PathAddress.pathAddress(SYSTEM_PROPERTY, OidcLogoutBaseTest.class.getName()));
        add.get(VALUE).set(clazz.getName());
        ManagementOperations.executeOperation(client.getControllerClient(), add);
    }

    public static class WildFlyServerSetupTask extends ManagementServerSetupTask {
        public WildFlyServerSetupTask() {
            super(createContainerConfigurationBuilder()
                    .setupScript(createScriptBuilder()
                            .startBatch()
                            .add(String.format("/subsystem=elytron/properties-realm=ApplicationRealm:write-attribute(name=users-properties.path,value=\"%s\")",
                                    USERS_PATH))
                            .add("/subsystem=elytron/properties-realm=ApplicationRealm:write-attribute(name=users-properties.plain-text,value=true)")
                            .add("/subsystem=elytron/properties-realm=ApplicationRealm:undefine-attribute(name=users-properties.relative-to)")
                            .add(String.format("/subsystem=elytron/properties-realm=ApplicationRealm:write-attribute(name=groups-properties.path,value=\"%s\")",
                                    ROLES_PATH))
                            .add("/subsystem=elytron/properties-realm=ApplicationRealm:undefine-attribute(name=groups-properties.relative-to)")

                            /* // rls debug */
                            .add("/subsystem=logging/logger=org.wildfly.security.http.oidc:add()")
                            .add("/subsystem=logging/logger=org.wildfly.security.http.oidc:write-attribute(name=level, value=TRACE)")

                            .endBatch()
                            .build())
                    .tearDownScript(createScriptBuilder()
                            .startBatch()
                            .add(String.format("/subsystem=elytron/properties-realm=ApplicationRealm:write-attribute(name=users-properties.path,value=\"%s\")",
                                    ORIGINAL_USERS_PATH))
                            .add(String.format("/subsystem=elytron/properties-realm=ApplicationRealm:write-attribute(name=users-properties.relative-to,value=\"%s\")",
                                    RELATIVE_TO))
                            .add("/subsystem=elytron/properties-realm=ApplicationRealm:undefine-attribute(name=users-properties.plain-text)")
                            .add(String.format("/subsystem=elytron/properties-realm=ApplicationRealm:write-attribute(name=groups-properties.path,value=\"%s\")",
                                    ORIGINAL_ROLES_PATH))
                            .add(String.format("/subsystem=elytron/properties-realm=ApplicationRealm:write-attribute(name=groups-properties.relative-to,value=\"%s\")",
                                    RELATIVE_TO))
                            /* // rls debug */
                            .add("/subsystem=logging/logger=org.wildfly.security.http.oidc:remove()")

                            .endBatch()
                            .build())
                    .build());
        }
    }
}
