/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client.logout;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.version.Stability;
import org.junit.runner.RunWith;
import org.wildfly.security.http.oidc.Oidc;
import org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration;
import org.wildfly.test.stabilitylevel.StabilityServerSetupSnapshotRestoreTasks;

/*  Root class for testing OIDC logout.  Logout configuration attributes
    are passed to Elytron via system properties.

    The contents of this class declare the configurable data required
    for Keycloak and Elytron.

    The WAR files used in testing are declared and deployed in the
    super class, OidcLogoutSystemPropertiesAppsSetUp.  Testing of
    login and logout functionality is performed in class
    OidcLogoutSystemPropertiesAppsExec
 */

@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({ OidcLogoutNoPostPathSystemPropertiesTest.PreviewStabilitySetupTask.class,
        OidcLogoutEnvSetup.KeycloakAndSystemPropertySetup.class,
        OidcLogoutEnvSetup.WildFlySystemPropertiesSetupTask.class,
        OidcLogoutEnvSetup.WildFlyServerSetupTask.class})
public class OidcLogoutNoPostPathSystemPropertiesTest extends OidcLogoutSystemPropertiesAppsSetUp{

    private static final String LOGOUT_PATH_SYS_PROP = "/mylogout";
    private static final String LOGOUT_CALLBACK_PATH_SYS_PROP = "/more/myCallback";
    private static final String POST_LOGOUT_PATH_SYS_PROP = "/myPath";

    // These are the oidc logout attribute names and corresponding values that
    // are created as system properties.
    // The values MUST be the same that are register for Keycloak. (see
    // APP_LOGOUT below)
    private static Map<String,String> LOGOUT_SYS_PROPS;
    static {
        LOGOUT_SYS_PROPS = new HashMap<>();
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_PATH, LOGOUT_PATH_SYS_PROP);
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_CALLBACK_PATH, LOGOUT_CALLBACK_PATH_SYS_PROP);
        //LOGOUT_SYS_PROPS.put(Oidc.POST_LOGOUT_PATH, POST_LOGOUT_PATH_SYS_PROP);
        OidcLogoutEnvSetup.WildFlySystemPropertiesSetupTask.setLogoutSysProps(LOGOUT_SYS_PROPS);
    }

    // These are the oidc logout URL paths that are registered with Keycloak.
    // The path of the URL must be the same as the system properties registered above.
    private static Map<String, OidcLogoutBaseTest.LogoutChannelPaths> APP_LOGOUT;
    static {
        APP_LOGOUT= new HashMap<>();
        APP_LOGOUT.put(RP_INITIATED_LOGOUT_APP, new OidcLogoutBaseTest.LogoutChannelPaths(
                null,null, null) );
        APP_LOGOUT.put(FRONT_CHANNEL_LOGOUT_APP, new OidcLogoutBaseTest.LogoutChannelPaths(null,
                SimpleSecuredServlet.SERVLET_PATH +
                        LOGOUT_CALLBACK_PATH_SYS_PROP,
                null) );
        APP_LOGOUT.put(BACK_CHANNEL_LOGOUT_APP, new OidcLogoutBaseTest.LogoutChannelPaths(
                SimpleSecuredServlet.SERVLET_PATH
                        + LOGOUT_CALLBACK_PATH_SYS_PROP,
                null, null) );
        APP_LOGOUT.put(POST_LOGOUT_APP, new OidcLogoutBaseTest.LogoutChannelPaths(
                null,null, List.of(POST_LOGOUT_PATH_SYS_PROP)) );

        OidcLogoutEnvSetup.KeycloakAndSystemPropertySetup.setLogoutUrlPaths(APP_LOGOUT);
    }

    // These are the application names registered as Keycloak clients.
    // The name corresponds to each WAR file declared and deployed in
    // OidcLogoutSystemPropertiesAppsSetUp
    private static Map<String, KeycloakConfiguration.ClientAppType> APP_NAMES;
    static {
        APP_NAMES = new HashMap<>();
        APP_NAMES.put(RP_INITIATED_LOGOUT_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(FRONT_CHANNEL_LOGOUT_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(BACK_CHANNEL_LOGOUT_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(POST_LOGOUT_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);

        OidcLogoutEnvSetup.KeycloakAndSystemPropertySetup.setKeycloakClients(APP_NAMES);
    }

    public OidcLogoutNoPostPathSystemPropertiesTest() {
        super(Stability.PREVIEW);
    }


    public static class PreviewStabilitySetupTask extends StabilityServerSetupSnapshotRestoreTasks.Preview {
        @Override
        protected void doSetup(ManagementClient managementClient) throws Exception {
            // Write a system property so the model gets stored with a lower stability level.
            // This is to make sure we can reload back to the higher level from the snapshot
            OidcLogoutSystemPropertiesAppsExec.addSystemProperty(managementClient,
                    OidcLogoutNoPostPathSystemPropertiesTest.class);
        }
    }
}
