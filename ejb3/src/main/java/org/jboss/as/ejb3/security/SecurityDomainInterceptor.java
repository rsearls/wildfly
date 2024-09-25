/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.jboss.as.ejb3.security;

import org.jboss.as.ejb3.logging.EjbLogger;
import org.jboss.invocation.Interceptor;
import org.jboss.invocation.InterceptorContext;
import org.wildfly.security.auth.server.SecurityDomain;

/**
 * An interceptor which sets the security domain of the invocation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class SecurityDomainInterceptor implements Interceptor {
    private final SecurityDomain securityDomain;

    SecurityDomainInterceptor(final SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
    }

    public Object processInvocation(final InterceptorContext context) throws Exception {
        final SecurityDomain oldDomain = context.putPrivateData(SecurityDomain.class, securityDomain);
        /** rls */
        EjbLogger.ROOT_LOGGER.trace("## ejb3.security.SecurityDomainInterceptor  oldDomain SecurityIdentity: "
        + (oldDomain == null ? "null" : oldDomain.getCurrentSecurityIdentity().toString())
                + ",  securityDomain SecurityIdentity: " + securityDomain.getCurrentSecurityIdentity().toString());
        /**/
        try {
            return context.proceed();
        } finally {
            context.putPrivateData(SecurityDomain.class, oldDomain);
        }
    }
}
