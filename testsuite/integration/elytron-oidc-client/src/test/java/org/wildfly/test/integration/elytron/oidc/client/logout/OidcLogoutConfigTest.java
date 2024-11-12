/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client.logout;

import static org.jboss.as.test.integration.management.util.ModelUtil.createOpNode;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.KEYSTORE_FILE_NAME;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.KEYSTORE_CLASSPATH;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.getRealmRepresentation;

import io.restassured.RestAssured;

import java.util.HashMap;
import java.util.Map;

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
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.representations.idm.RealmRepresentation;
import org.wildfly.test.integration.elytron.oidc.client.deployment.OidcWithDeploymentConfigTest;
import org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration;
import org.wildfly.test.stabilitylevel.StabilityServerSetupSnapshotRestoreTasks;

/**
 * Tests for the OpenID Connect authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({ OidcLogoutConfigTest.PreviewStabilitySetupTask.class,
        OidcLogoutConfigTest.KeycloakAndSystemPropertySetup.class,
        OidcLogoutBaseTest.WildFlyServerSetupTask.class})
public class OidcLogoutConfigTest extends OidcLogoutBaseTest {

    private static final String OIDC_PROVIDER_URL = "oidc.provider.url";
    private static final String OIDC_JSON_WITH_PROVIDER_URL_FILE = "OidcWithProviderUrl.json";

    private static final String OIDC_AUTH_SERVER_URL = "oidc.auth.server.url";
    private static final String OIDC_JSON_WITH_AUTH_SERVER_URL_FILE = "OidcWithAuthServerUrl.json";

    private static final String OIDC_REST_AUTH_SERVER_URL = "oidc.rest.auth.server.url";
    private static final String OIDC_JSON_WITH_REST_AUTH_SERVER_URL_FILE = "OidcWithRestAuthServerUrl.json";

    private static final String WRONG_OIDC_PROVIDER_URL = "wrong.oidc.provider.url";
    private static final String OIDC_REQUEST_OBJECT_SIGNING_KEYSTORE_FILE = "oidc.request.object.signing.keystore.file";

    private static Map<String, KeycloakConfiguration.ClientAppType> APP_NAMES;
    static {
        APP_NAMES = new HashMap<>();
        APP_NAMES.put(AUTH_SERVER_URL_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(REST_AUTH_SERVER_URL_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
    }


    private static Map<String, LogoutChannelPaths> APP_LOGOUT;
    static {
        APP_LOGOUT= new HashMap<>();
        // todo fix mapping to created uri
        APP_LOGOUT.put(REST_AUTH_SERVER_URL_APP,
                new LogoutChannelPaths(
                        SimpleSecuredServlet.SERVLET_PATH+RP_INITIATED_LOGOUT_PATH,
                null, null) );
    }

    public OidcLogoutConfigTest() {
        super(Stability.PREVIEW);
    }

    @ArquillianResource
    protected static Deployer deployer;

    //------------------ KEEP  start -------------------
    @Deployment(name = AUTH_SERVER_URL_APP, managed = false, testable = false)
    public static WebArchive createAuthServerUrlDeployment() {
        return ShrinkWrap.create(WebArchive.class, AUTH_SERVER_URL_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleSecuredServlet.class)
                .addAsWebInfResource(OidcWithDeploymentConfigTest.class.getPackage(), OIDC_WITHOUT_SUBSYSTEM_CONFIG_WEB_XML, "web.xml")
                .addAsWebInfResource(OidcWithDeploymentConfigTest.class.getPackage(), OIDC_JSON_WITH_AUTH_SERVER_URL_FILE, "oidc.json");
    }
    //------------------ KEEP  end -------------------

    @Deployment(name = REST_AUTH_SERVER_URL_APP, managed = false, testable = false)
    public static WebArchive createRestAuthServerUrlDeployment() {
        return ShrinkWrap.create(WebArchive.class, REST_AUTH_SERVER_URL_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleSecuredServlet.class)
                .addClass(AnOidcSimpleResource.class)
                .addAsWebInfResource(OidcLogoutConfigTest.class.getPackage(), OIDC_WITHOUT_SUBSYSTEM_CONFIG_WEB_XML, "web.xml")
                .addAsWebInfResource(OidcLogoutConfigTest.class.getPackage(), OIDC_JSON_WITH_REST_AUTH_SERVER_URL_FILE, "oidc.json")
        ;
    }

    //------------------ KEEP  start -------------------

    @Test
    @InSequence(1)
    public void testOidcLogout() throws Exception {
        try {
            deployer.deploy(REST_AUTH_SERVER_URL_APP);
            super.testOidcLogout();
        } finally {
            deployer.undeploy(REST_AUTH_SERVER_URL_APP);
        }
    }
    //------------------ KEEP  end -------------------

    static class KeycloakAndSystemPropertySetup extends KeycloakSetup {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            super.setup(managementClient, containerId);
            RealmRepresentation realm = getRealmRepresentation(TEST_REALM,
                    CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, APP_NAMES);
            setOidcLogoutUrls(realm, APP_NAMES, APP_LOGOUT);
            sendRealmCreationRequest(realm);

            ModelControllerClient client = managementClient.getControllerClient();
            ModelNode operation = createOpNode("system-property=" + OIDC_PROVIDER_URL, ModelDescriptionConstants.ADD);
            operation.get("value").set(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM);
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + OIDC_AUTH_SERVER_URL, ModelDescriptionConstants.ADD);
            operation.get("value").set(KEYCLOAK_CONTAINER.getAuthServerUrl());
            Utils.applyUpdate(operation, client);

            operation = createOpNode("system-property=" + OIDC_REST_AUTH_SERVER_URL, ModelDescriptionConstants.ADD);
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
            OidcLogoutBaseTest.addSystemProperty(managementClient, OidcLogoutConfigTest.class);
        }
    }
}
