/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client.logout;

import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.InSequence;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.test.integration.security.common.servlets.SimpleSecuredServlet;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.as.version.Stability;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import java.util.HashMap;
import java.util.Map;
import org.wildfly.security.http.oidc.Oidc;
import org.jboss.as.arquillian.container.ManagementClient;

/**
 * Tests for the OpenID Connect authentication mechanism.
 *
 */
public class OidcLogoutSystemPropertiesAppsSetUp extends OidcLogoutSystemPropertiesAppsExec {

    private static final String WEB_XML = "web.xml";

    public OidcLogoutSystemPropertiesAppsSetUp(){}
    public OidcLogoutSystemPropertiesAppsSetUp(Stability desiredStability) {
        super(desiredStability);
    }

    @ArquillianResource
    protected static Deployer deployer;

    //@ArquillianResource
    //protected static ManagementClient managementClient;

    private static final Package packageName = OidcLogoutSystemPropertiesAppsSetUp.class.getPackage();

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

    @Deployment(name = BACK_CHANNEL_LOGOUT_APP, managed = false, testable = false)
    public static WebArchive createBackChannelAuthServerUrlDeployment() {
        WebArchive war =  ShrinkWrap.create(WebArchive.class, BACK_CHANNEL_LOGOUT_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleSecuredServlet.class)
                .addAsWebInfResource(packageName, WEB_XML, "web.xml")
                .addAsWebInfResource(packageName,
                        BACK_CHANNEL_LOGOUT_APP+"-oidc.json", "oidc.json")
                ;
        return war;
    }

    @Deployment(name = POST_LOGOUT_APP, managed = false, testable = false)
    public static WebArchive createPostLogoutApp() {
        return ShrinkWrap.create(WebArchive.class, POST_LOGOUT_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleSecuredServlet.class)
                .addAsWebInfResource(packageName, WEB_XML, "web.xml")
                .addAsWebInfResource(packageName,
                        POST_LOGOUT_APP+"-oidc.json", "oidc.json")
                ;
    }
    @Test
    @InSequence(1)
    //  Test checks that RPInitiated Logout can be completed
    //  via a GET to the OP.
    public void testRpInitiatedLogout() throws Exception {
        /* -- rls
        Map<String,String> LOGOUT_SYS_PROPS = new HashMap<>();
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_PATH, "/mylogout");
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_CALLBACK_PATH, "/more/myCallback");
        LOGOUT_SYS_PROPS.put(Oidc.POST_LOGOUT_PATH, "http://" + EnvSetupUtils.CLIENT_HOST_NAME + ":"
                + EnvSetupUtils.CLIENT_PORT + "/" + RP_INITIATED_LOGOUT_APP
                + SimplePostLogoutServlet.POST_LOGOUT_PATH);
        -- rls */
        /* -- rls
        System.setProperty(Oidc.LOGOUT_PATH, "/mylogout");
        System.setProperty(Oidc.LOGOUT_CALLBACK_PATH, "/more/myCallback");
        System.setProperty(Oidc.POST_LOGOUT_PATH, "http://" + EnvSetupUtils.CLIENT_HOST_NAME + ":"
                + EnvSetupUtils.CLIENT_PORT + "/" + RP_INITIATED_LOGOUT_APP
                + SimplePostLogoutServlet.POST_LOGOUT_PATH);
        -- rls */
        try {
            deployer.deploy(RP_INITIATED_LOGOUT_APP);
            super.testRpInitiatedLogout();
        } finally {
            /* -- rls
            System.clearProperty(Oidc.LOGOUT_PATH);
            System.clearProperty(Oidc.LOGOUT_CALLBACK_PATH);
            System.clearProperty(Oidc.POST_LOGOUT_PATH);
            -- rls */
            //clearSystemProperties(EnvSetupUtils.KeycloakAndSystemPropertySetup.mgtClient);
            deployer.undeploy(RP_INITIATED_LOGOUT_APP);
        }
    }

    @Test
    @InSequence(2)
    //  Test checks that front channel Logout can be completed.
    public void testFrontChannelLogout() throws Exception {
    /* -------- rls
        try {
            deployer.deploy(FRONT_CHANNEL_LOGOUT_APP);
            super.testFrontChannelLogout();
        } finally {
            deployer.undeploy(FRONT_CHANNEL_LOGOUT_APP);
        }
 -------- rls */
    }

    @Test
    @InSequence(3)
    //  Test checks that back channel Logout can be completed.
    public void testBackChannelLogout() throws Exception {
        /* --- rls
        Map<String,String> LOGOUT_SYS_PROPS = new HashMap<>();
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_PATH, "/XXmylogout");
        LOGOUT_SYS_PROPS.put(Oidc.LOGOUT_CALLBACK_PATH, "/more/XXmyCallback");
        LOGOUT_SYS_PROPS.put(Oidc.POST_LOGOUT_PATH, "/XXpostRedirect");
        --- rls */
        /* -- rls
        System.setProperty(Oidc.LOGOUT_PATH, "/XXmylogout");
        System.setProperty(Oidc.LOGOUT_CALLBACK_PATH, "/more/XXmyCallback");
        System.setProperty(Oidc.POST_LOGOUT_PATH, "/XXpostRedirect");
        -- rls */
        try {
            deployer.deploy(BACK_CHANNEL_LOGOUT_APP);
            super.testBackChannelLogout();
        } finally {
            /* -- rls
            System.clearProperty(Oidc.LOGOUT_PATH);
            System.clearProperty(Oidc.LOGOUT_CALLBACK_PATH);
            System.clearProperty(Oidc.POST_LOGOUT_PATH);
            -- rls */
            //clearSystemProperties(EnvSetupUtils.KeycloakAndSystemPropertySetup.mgtClient);
            deployer.undeploy(BACK_CHANNEL_LOGOUT_APP);
        }

    }

    @Test
    @InSequence(4)
    //  Test checks that post Logout callback.
    public void testPostLogout() throws Exception {
        /* --- rls
        try {
            deployer.deploy(POST_LOGOUT_APP);
            super.testPostLogout();
        } finally {
            deployer.undeploy(POST_LOGOUT_APP);
        }
        --- rls */
    }

    @Test
    @InSequence(5)
    // Test checks that back channel Logout can be completed
    // when user logged in to 2 apps
    public void testBackChannelLogoutTwo() throws Exception {
        /* --- rls
        try {
            deployer.deploy(FRONT_CHANNEL_LOGOUT_APP);
            deployer.deploy(BACK_CHANNEL_LOGOUT_APP);
            super.testBackChannelLogout();
        } finally {
            deployer.undeploy(FRONT_CHANNEL_LOGOUT_APP);
            deployer.undeploy(BACK_CHANNEL_LOGOUT_APP);
        }
        --- rls */
    }

}
