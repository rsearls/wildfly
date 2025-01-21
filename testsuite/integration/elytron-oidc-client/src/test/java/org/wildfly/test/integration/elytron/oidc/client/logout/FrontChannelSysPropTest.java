/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client.logout;


import static org.junit.Assume.assumeTrue;
import static org.wildfly.test.integration.elytron.oidc.client.logout.Constants.FRONT_CHANNEL_LOGOUT_APP;
import static org.wildfly.test.integration.elytron.oidc.client.logout.Constants.WEB_XML;

import java.util.HashMap;
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
import org.wildfly.test.integration.elytron.oidc.client.logout.LoginLogoutBasics.LogoutChannelPaths;
import org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration;
import org.wildfly.test.stabilitylevel.StabilityServerSetupSnapshotRestoreTasks;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/*  todo requires browser for testing
    Test OIDC front-channel logout.  Logout configuration attributes
    are passed to Elytron via system properties.
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({ FrontChannelSysPropTest.PreviewStabilitySetupTask.class,
        EnvSetupUtils.KeycloakAndSystemPropertySetup.class,
        EnvSetupUtils.WildFlySystemPropertiesSetupTask.class,
        EnvSetupUtils.WildFlyServerSetupTask.class})
public class FrontChannelSysPropTest extends LoginLogoutBasics {

    @ArquillianResource
    protected static Deployer deployer;

    @BeforeClass
    public static void checkDockerAvailability() {
        assumeTrue("Docker isn't available, OIDC tests will be skipped",
                AssumeTestGroupUtil.isDockerAvailable());
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

    public FrontChannelSysPropTest() {
        super(Stability.PREVIEW);
    }

    //-------------- test configuration data ---------------
    // These are the oidc logout attribute names and corresponding values that
    // are created as system properties.
    // The values MUST be the same that are register for Keycloak. (see
    // APP_LOGOUT below)
    private static Map<String,String> LOGOUT_SYS_PROPS;
    static {
        LOGOUT_SYS_PROPS = new HashMap<>();
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_PATH, Constants.LOGOUT_PATH_VALUE);
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_CALLBACK_PATH, Constants.LOGOUT_CALLBACK_PATH_VALUE);
        EnvSetupUtils.WildFlySystemPropertiesSetupTask.setLogoutSysProps(LOGOUT_SYS_PROPS);
    }

    // These are the oidc logout URL paths that are registered with Keycloak.
    // The path of the URL must be the same as the system properties registered above.
    private static Map<String, LogoutChannelPaths> APP_LOGOUT;
    static {
        APP_LOGOUT= new HashMap<String, LogoutChannelPaths>();
        APP_LOGOUT.put(FRONT_CHANNEL_LOGOUT_APP, new LogoutChannelPaths(
                null,null, null) );
        EnvSetupUtils.KeycloakAndSystemPropertySetup.setLogoutUrlPaths(APP_LOGOUT);
    }

    // These are the application names registered as Keycloak clients.
    // The name corresponds to each WAR file declared and deployed in
    // OidcLogoutSystemPropertiesAppsSetUp
    private static Map<String, KeycloakConfiguration.ClientAppType> APP_NAMES;
    static {
        APP_NAMES = new HashMap<>();
        APP_NAMES.put(FRONT_CHANNEL_LOGOUT_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        EnvSetupUtils.KeycloakAndSystemPropertySetup.setKeycloakClients(APP_NAMES);
    }

    //-------------- Test components ---------------------

    private static final Package packageName = FrontChannelSysPropTest.class.getPackage();

    @Deployment(name = FRONT_CHANNEL_LOGOUT_APP, managed = false, testable = false)
    public static WebArchive createFrontChannelAuthServerUrlDeployment() {
        return ShrinkWrap.create(WebArchive.class, FRONT_CHANNEL_LOGOUT_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleSecuredServlet.class)
                .addAsWebInfResource(packageName, WEB_XML, "web.xml")
                .addAsWebInfResource(packageName,
                        FRONT_CHANNEL_LOGOUT_APP+"-oidc.json", "oidc.json")
                ;
    }

    @Test
    //  Test checks that front channel Logout can be completed.
    public void testFrontChannelLogout() throws Exception {
    /* -------- rls  todo requires Browser test env
        try {
            deployer.deploy(FRONT_CHANNEL_LOGOUT_APP);

            loginToApp(FRONT_CHANNEL_LOGOUT_APP);
            assertUserLoggedIn(FRONT_CHANNEL_LOGOUT_APP, SimpleServlet.RESPONSE_BODY);
            logoutOfKeycloak(FRONT_CHANNEL_LOGOUT_APP, "You are logging out from following apps");
            assertUserLoggedOut(FRONT_CHANNEL_LOGOUT_APP, SimpleServlet.RESPONSE_BODY); // todo fix rls

        } finally {
            deployer.undeploy(FRONT_CHANNEL_LOGOUT_APP);
        }
 -------- rls */
    }


    //-------------- Server Setup -------------------------
    public static class PreviewStabilitySetupTask extends StabilityServerSetupSnapshotRestoreTasks.Preview {
        @Override
        protected void doSetup(ManagementClient managementClient) throws Exception {
            // Write a system property so the model gets stored with a lower stability level.
            // This is to make sure we can reload back to the higher level from the snapshot
            LoginLogoutBasics.addSystemProperty(managementClient, FrontChannelSysPropTest.class);
        }
    }
}
