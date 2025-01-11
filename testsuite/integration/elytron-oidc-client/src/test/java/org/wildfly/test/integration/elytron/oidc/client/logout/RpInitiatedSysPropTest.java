/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client.logout;


import static org.junit.Assume.assumeTrue;
import static org.wildfly.test.integration.elytron.oidc.client.logout.Constants.RP_INITIATED_LOGOUT_APP;
import static org.wildfly.test.integration.elytron.oidc.client.logout.Constants.WEB_XML;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.LaxRedirectStrategy;

import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.test.http.util.TestHttpClientUtils;
import org.jboss.as.test.shared.util.AssumeTestGroupUtil;
import org.jboss.as.version.Stability;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;

import org.wildfly.security.http.oidc.Oidc;
import org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration;
import org.wildfly.test.stabilitylevel.StabilityServerSetupSnapshotRestoreTasks;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/*  Test OIDC Rp-Initiated logout.  Logout configuration attributes
    are passed to Elytron via system properties.
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({ RpInitiatedSysPropTest.PreviewStabilitySetupTask.class,
        EnvSetupUtils.KeycloakAndSystemPropertySetup.class,
        EnvSetupUtils.WildFlySystemPropertiesSetupTask.class,
        EnvSetupUtils.WildFlyServerSetupTask.class})
public class RpInitiatedSysPropTest extends LoginLogoutBasics {

    @ArquillianResource
    protected static Deployer deployer;

    @BeforeClass
    public static void checkDockerAvailability() {
        assumeTrue("Docker isn't available, OIDC tests will be skipped", AssumeTestGroupUtil.isDockerAvailable());
    }

    @Before
    public void createHttpClient() {
        CookieStore store = new BasicCookieStore();
        HttpClient httpClient = TestHttpClientUtils.promiscuousCookieHttpClientBuilder()
                .setDefaultCookieStore(store)
                .setRedirectStrategy(new LaxRedirectStrategy())
                .build();
        super.setHttpClient(httpClient);
    }

    public RpInitiatedSysPropTest() {
        super(Stability.PREVIEW);
    }

    //-------------- test configuration data ---------------
    private static final String LOGOUT_PATH_SYS_PROP = "/mylogout";
    private static final String LOGOUT_CALLBACK_PATH_SYS_PROP = "/more/myCallback";
    private static final String POST_LOGOUT_PATH_SYS_PROP = "http://" + EnvSetupUtils.CLIENT_HOST_NAME + ":"
            + EnvSetupUtils.CLIENT_PORT + "/" + RP_INITIATED_LOGOUT_APP
            + SimplePostLogoutServlet.POST_LOGOUT_PATH;

    // These are the oidc logout attribute names and corresponding values that
    // are created as system properties.
    // The values MUST be the same that are register for Keycloak. (see
    // APP_LOGOUT below)
    private static Map<String,String> LOGOUT_SYS_PROPS;
    static {
        LOGOUT_SYS_PROPS = new HashMap<>();
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_PATH, LOGOUT_PATH_SYS_PROP);
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_CALLBACK_PATH, LOGOUT_CALLBACK_PATH_SYS_PROP);
        LOGOUT_SYS_PROPS.put(Oidc.POST_LOGOUT_PATH, POST_LOGOUT_PATH_SYS_PROP);
        EnvSetupUtils.WildFlySystemPropertiesSetupTask.setLogoutSysProps(LOGOUT_SYS_PROPS);
    }

    // These are the oidc logout URL paths that are registered with Keycloak.
    // The path of the URL must be the same as the system properties registered above.
    private static Map<String, OidcLogoutBaseTest.LogoutChannelPaths> APP_LOGOUT;
    static {
        APP_LOGOUT= new HashMap<String, OidcLogoutBaseTest.LogoutChannelPaths>();
        APP_LOGOUT.put(RP_INITIATED_LOGOUT_APP, new OidcLogoutBaseTest.LogoutChannelPaths(
                null,null, List.of(POST_LOGOUT_PATH_SYS_PROP)) );
        EnvSetupUtils.KeycloakAndSystemPropertySetup.setLogoutUrlPaths(APP_LOGOUT);
    }

    // These are the application names registered as Keycloak clients.
    // The name corresponds to each WAR file declared and deployed in
    // OidcLogoutSystemPropertiesAppsSetUp
    private static Map<String, KeycloakConfiguration.ClientAppType> APP_NAMES;
    static {
        APP_NAMES = new HashMap<>();
        APP_NAMES.put(RP_INITIATED_LOGOUT_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        EnvSetupUtils.KeycloakAndSystemPropertySetup.setKeycloakClients(APP_NAMES);
    }

    //-------------- Test components ---------------------

    private static final Package packageName = RpInitiatedSysPropTest.class.getPackage();

    @Deployment(name = RP_INITIATED_LOGOUT_APP, managed = false, testable = false)
    public static WebArchive createRpInitiatedAuthServerUrlDeployment() {
        return ShrinkWrap.create(WebArchive.class, RP_INITIATED_LOGOUT_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleSecuredServlet.class)
                .addClasses(SimplePostLogoutServlet.class)
                .addAsWebInfResource(packageName, WEB_XML, "web.xml")
                .addAsWebInfResource(packageName,
                        RP_INITIATED_LOGOUT_APP+"-oidc.json", "oidc.json")
                ;
    }

    @Test
    //  Test checks that RPInitiated Logout can be completed
    //  via a GET to the OP.
    public void testRpInitiatedLogout() throws Exception {
        try {
            deployer.deploy(RP_INITIATED_LOGOUT_APP);

            loginToApp(RP_INITIATED_LOGOUT_APP);
            assertUserLoggedIn(RP_INITIATED_LOGOUT_APP, SimpleServlet.RESPONSE_BODY);
            logoutOfKeycloak(RP_INITIATED_LOGOUT_APP, SimplePostLogoutServlet.RESPONSE_BODY);
            assertUserLoggedOut(RP_INITIATED_LOGOUT_APP, SimpleServlet.RESPONSE_BODY);

        } finally {
            deployer.undeploy(RP_INITIATED_LOGOUT_APP);
        }
    }


    //-------------- Server Setup -------------------------
    public static class PreviewStabilitySetupTask extends StabilityServerSetupSnapshotRestoreTasks.Preview {
        @Override
        protected void doSetup(ManagementClient managementClient) throws Exception {
            // Write a system property so the model gets stored with a lower stability level.
            // This is to make sure we can reload back to the higher level from the snapshot
            LoginLogoutBasics.addSystemProperty(managementClient, RpInitiatedSysPropTest.class);
        }
    }
}