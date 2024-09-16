/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client.deployment;

import io.restassured.RestAssured;
import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.junit.InSequence;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration;
import org.wildfly.test.integration.elytron.oidc.client.SimplifiedOidcBaseTest;
import org.wildfly.test.stabilitylevel.StabilityServerSetupSnapshotRestoreTasks;

import java.util.HashMap;
import java.util.Map;

import static org.jboss.as.test.integration.management.util.ModelUtil.createOpNode;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.KEYSTORE_CLASSPATH;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.KEYSTORE_FILE_NAME;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.getRealmRepresentation;

/**
 * Tests for the OpenID Connect authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 *
 */
/*  rls
,
        SimplifiedOidcBaseTest.WildFlyServerSetupTask.class
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({ SimplifiedOidcWithDeploymentConfigTest.PreviewStabilitySetupTask.class,
        SimplifiedOidcWithDeploymentConfigTest.KeycloakAndSystemPropertySetup.class})
public class SimplifiedOidcWithDeploymentConfigTest extends SimplifiedOidcBaseTest {

    private static final String OIDC_PROVIDER_URL = "oidc.provider.url";
    private static final String OIDC_JSON_WITH_PROVIDER_URL_FILE = "OidcWithProviderUrl.json";

    private static final String OIDC_AUTH_SERVER_URL = "oidc.auth.server.url";
    private static final String OIDC_JSON_WITH_AUTH_SERVER_URL_FILE = "OidcWithAuthServerUrl.json";

    private static final String WRONG_OIDC_PROVIDER_URL = "wrong.oidc.provider.url";
    private static final String OIDC_REQUEST_OBJECT_SIGNING_KEYSTORE_FILE = "oidc.request.object.signing.keystore.file";
    private static final String OIDC_JSON_WITH_WRONG_PROVIDER_URL_FILE = "OidcWithWrongProviderUrl.json";

    private static final String OIDC_JSON_WITH_WRONG_SECRET_FILE = "OidcWithWrongSecret.json";

    private static final String MISSING_EXPRESSION_APP = "MissingExpressionOidcApp";
    private static final String OIDC_JSON_WITH_MISSING_EXPRESSION_FILE = "OidcWithMissingExpression.json";

    private static final String BEARER_ONLY_WITH_AUTH_SERVER_URL_FILE = "BearerOnlyWithAuthServerUrl.json";

    private static final String BEARER_ONLY_WITH_PROVIDER_URL_FILE = "BearerOnlyWithProviderUrl.json";
    private static final String BASIC_AUTH_WITH_PROVIDER_URL_FILE = "BasicAuthWithProviderUrl.json";
    private static final String CORS_WITH_PROVIDER_URL_FILE = "CorsWithProviderUrl.json";
    private static final String SINGLE_SCOPE_FILE = "OidcWithSingleScope.json";
    private static final String MULTI_SCOPE_FILE = "OidcWithMultipleScopes.json";
    private static final String INVALID_SCOPE_FILE = "OidcWithInvalidScope.json";
    private static final String OPENID_SCOPE_FILE = "OidcWithOpenIDScope.json";
    private static final String OAUTH2_REQUEST_FILE = "OidcWithOauth2Request.json";
    private static final String PLAIN_TEXT_REQUEST_FILE = "OidcWithPlainTextRequest.json";
    private static final String PLAIN_TEXT_REQUEST_URI_FILE = "OidcWIthPlainTextRequestUri.json";
    private static final String PLAIN_TEXT_ENCRYPTED_REQUEST_FILE = "OidcWithPlainTextEncryptedRequest.json";
    private static final String PLAIN_TEXT_ENCRYPTED_REQUEST_URI_FILE = "OidcWithPlainTextEncryptedRequestUri.json";
    private static final String RSA_SIGNED_REQUEST_FILE = "OidcWIthRsaSignedRequest.json";
    private static final String RSA_SIGNED_AND_ENCRYPTED_REQUEST_FILE = "OidcWithRsaSignedAndEncryptedRequest.json";
    private static final String SIGNED_AND_ENCRYPTED_REQUEST_URI_FILE = "OidcWithSignedAndEncryptedRequestUri.json";
    private static final String PS_SIGNED_RSA_ENCRYPTED_REQUEST_FILE = "OidcWithPsSignedRsaEncryptedRequest.json";
    private static final String PS_SIGNED_REQUEST_URI_FILE = "OidcWithPsSignedRequestUri.json";
    private static final String INVALID_SIGNATURE_ALGORITHM_FILE = "OidcWithInvalidSigningAlgorithm.json";
    private static final String MISSING_SECRET_WITH_HMAC_ALGORITHM_FILE = "MissingSecretWithHmacAlgorithm.json";

    private static Map<String, KeycloakConfiguration.ClientAppType> APP_NAMES;
    static {
        APP_NAMES = new HashMap<>();
        /**
        APP_NAMES.put(PROVIDER_URL_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(AUTH_SERVER_URL_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(WRONG_PROVIDER_URL_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(WRONG_SECRET_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(MISSING_EXPRESSION_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(DIRECT_ACCCESS_GRANT_ENABLED_CLIENT, KeycloakConfiguration.ClientAppType.DIRECT_ACCESS_GRANT_OIDC_CLIENT);
        APP_NAMES.put(BEARER_ONLY_AUTH_SERVER_URL_APP, KeycloakConfiguration.ClientAppType.BEARER_ONLY_CLIENT);
        APP_NAMES.put(BEARER_ONLY_PROVIDER_URL_APP, KeycloakConfiguration.ClientAppType.BEARER_ONLY_CLIENT);
        APP_NAMES.put(BASIC_AUTH_PROVIDER_URL_APP, KeycloakConfiguration.ClientAppType.BEARER_ONLY_CLIENT);
        APP_NAMES.put(CORS_PROVIDER_URL_APP, KeycloakConfiguration.ClientAppType.BEARER_ONLY_CLIENT);
        APP_NAMES.put(CORS_CLIENT, KeycloakConfiguration.ClientAppType.CORS_CLIENT);
        APP_NAMES.put(SINGLE_SCOPE_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(MULTIPLE_SCOPE_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(INVALID_SCOPE_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(OPENID_SCOPE_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(OAUTH2_REQUEST_METHOD_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(PLAINTEXT_REQUEST_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(PLAINTEXT_REQUEST_URI_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(PLAINTEXT_ENCRYPTED_REQUEST_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(PLAINTEXT_ENCRYPTED_REQUEST_URI_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(RSA_SIGNED_AND_ENCRYPTED_REQUEST_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(SIGNED_AND_ENCRYPTED_REQUEST_URI_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(PS_SIGNED_RSA_ENCRYPTED_REQUEST_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(RSA_SIGNED_REQUEST_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(PS_SIGNED_REQUEST_URI_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(INVALID_SIGNATURE_ALGORITHM_FILE, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(MISSING_SECRET_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(FORM_WITH_OIDC_OIDC_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
         rls ****/
    }

    public SimplifiedOidcWithDeploymentConfigTest() {
        super(Stability.PREVIEW);
    }

    @ArquillianResource
    protected static Deployer deployer;

    @Deployment(name = FORM_WITH_OIDC_EAR_APP, managed = false, testable = false)
    public static Archive<?> createFormWithOidcDeployment() {
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, FORM_WITH_OIDC_EAR_APP+".ear");
        ear.addAsManifestResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP+"_application.xml", "application.xml");

        final WebArchive form = ShrinkWrap.create(WebArchive.class, "form.war");
        form.addClasses(SimpleServlet.class);
        form.addClasses(SimpleSecuredServlet.class);
        form.addAsWebInfResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP + "_form_web.xml", "web.xml");
        form.addAsWebInfResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP + "_form_jboss-web.xml", "jboss-web.xml");
        form.addAsWebResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP + "_login.jsp", "login.jsp");
        form.addAsWebResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP + "_error.jsp", "error.jsp");

        ear.addAsModule(form);

        final WebArchive oidc = ShrinkWrap.create(WebArchive.class, "oidc.war");
        oidc.addClasses(SimpleServlet.class);
        oidc.addClasses(SimpleSecuredServlet.class);
        oidc.addAsWebInfResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP+"_oidc_web.xml", "web.xml");
        oidc.addAsWebInfResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP+"_oidc_jboss-web.xml", "jboss-web.xml");
        oidc.addAsWebInfResource(SimplifiedOidcWithDeploymentConfigTest.class.getPackage(),
                FORM_WITH_OIDC_EAR_APP+"_oidc_oidc.json", "oidc.json");
        ear.addAsModule(oidc);

        return ear;
    }

    @Test
    @InSequence(1)
    public void testFormWithOidc() throws Exception {
        try {
            deployer.deploy(FORM_WITH_OIDC_EAR_APP);
            super.testFormWithOidc();
        } finally {
            deployer.undeploy(FORM_WITH_OIDC_EAR_APP);
        }
    }

    @Test
    @InSequence(2)
    public void testInvalidFormWithOidcCredentials() throws Exception {
        try {
            deployer.deploy(FORM_WITH_OIDC_EAR_APP);
            super.testInvalidFormWithOidcCredentials();
        } finally {
            deployer.undeploy(FORM_WITH_OIDC_EAR_APP);
        }
    }

    static class KeycloakAndSystemPropertySetup extends KeycloakSetup {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            super.setup(managementClient, containerId);
            sendRealmCreationRequest(getRealmRepresentation(TEST_REALM, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, APP_NAMES));

            ModelControllerClient client = managementClient.getControllerClient();
            ModelNode operation = createOpNode("system-property=" + OIDC_PROVIDER_URL, ModelDescriptionConstants.ADD);
            operation.get("value").set(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM);
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + OIDC_AUTH_SERVER_URL, ModelDescriptionConstants.ADD);
            operation.get("value").set(KEYCLOAK_CONTAINER.getAuthServerUrl());
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + WRONG_OIDC_PROVIDER_URL, ModelDescriptionConstants.ADD);
            operation.get("value").set("http://fakeauthserver/auth"); // provider url does not exist
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + OIDC_REQUEST_OBJECT_SIGNING_KEYSTORE_FILE, ModelDescriptionConstants.ADD);
            operation.get("value").set(KEYSTORE_CLASSPATH + KEYSTORE_FILE_NAME);
            Utils.applyUpdate(operation, client);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            RestAssured
                    .given()
                    .auth().oauth2(org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM).then().statusCode(204);

            super.tearDown(managementClient, containerId);
            ModelControllerClient client = managementClient.getControllerClient();
            ModelNode operation = createOpNode("system-property=" + OIDC_PROVIDER_URL, ModelDescriptionConstants.REMOVE);
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + OIDC_AUTH_SERVER_URL, ModelDescriptionConstants.REMOVE);
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + WRONG_OIDC_PROVIDER_URL, ModelDescriptionConstants.REMOVE);
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + OIDC_REQUEST_OBJECT_SIGNING_KEYSTORE_FILE, ModelDescriptionConstants.REMOVE);
            Utils.applyUpdate(operation, client);
        }
    }

    public static class PreviewStabilitySetupTask extends StabilityServerSetupSnapshotRestoreTasks.Preview {
        @Override
        protected void doSetup(ManagementClient managementClient) throws Exception {
            // Write a system property so the model gets stored with a lower stability level.
            // This is to make sure we can reload back to the higher level from the snapshot
            SimplifiedOidcBaseTest.addSystemProperty(managementClient, SimplifiedOidcWithDeploymentConfigTest.class);
        }
    }
}
