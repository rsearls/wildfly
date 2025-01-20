/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.test.integration.elytron.oidc.client.logout;

public class Constants {
    public static final String RP_INITIATED_LOGOUT_APP = "RpInitiatedLogoutApp";
    public static final String BACK_CHANNEL_LOGOUT_APP = "BackChannelLogoutApp";
    public static final String FRONT_CHANNEL_LOGOUT_APP = "FrontChannelLogoutApp";
    public static final String WEB_XML = "web.xml";

    public static final String LOGOUT_PATH_SYS_PROP = "/mylogout";
    public static final String LOGOUT_CALLBACK_PATH_SYS_PROP = "/more/myCallback";

    public static final String SIGN_IN_TO_YOUR_ACCOUNT = "Sign in to your account";
    public static final String YOU_ARE_LOGGED_OUT = "You are logged out";
}
