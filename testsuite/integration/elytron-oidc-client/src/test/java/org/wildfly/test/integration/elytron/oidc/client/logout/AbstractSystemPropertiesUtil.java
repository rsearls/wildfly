/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.test.integration.elytron.oidc.client.logout;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AbstractSystemPropertiesUtil {
    private SystemProperty[] systemProperties;

    // Public methods --------------------------------------------------------

    public static SystemProperty[] mapToSystemProperties(Map<String, String> map) {
        if (map == null || map.isEmpty()) {
            return null;
        }
        final List<SystemProperty> list = new ArrayList<SystemProperty>();
        for (Map.Entry<String, String> property : map.entrySet()) {
            list.add(new DefaultSystemProperty(property.getKey(), property.getValue()));
        }
        return list.toArray(new SystemProperty[list.size()]);
    }

    // Embedded classes ------------------------------------------------------

    public interface SystemProperty {
        String getName();

        String getValue();

    }

    public static class DefaultSystemProperty implements SystemProperty {
        private final String name;
        private final String value;

        /**
         * Create a new DefaultSystemProperty.
         *
         * @param name
         * @param value
         */
        public DefaultSystemProperty(String name, String value) {
            super();
            this.name = name;
            this.value = value;
        }

        /**
         * Get the name.
         *
         * @return the name.
         */
        public String getName() {
            return name;
        }

        /**
         * Get the value.
         *
         * @return the value.
         */
        public String getValue() {
            return value;
        }

    }
}