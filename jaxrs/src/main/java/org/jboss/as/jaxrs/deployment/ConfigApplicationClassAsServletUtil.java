package org.jboss.as.jaxrs.deployment;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.jboss.as.jaxrs.JaxrsAnnotations;
import org.jboss.as.jaxrs.logging.JaxrsLogger;
import org.jboss.as.server.deployment.DeploymentUnitProcessingException;
import org.jboss.as.server.deployment.annotation.CompositeIndex;
import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.MethodInfo;
import org.jboss.metadata.javaee.spec.ParamValueMetaData;
import org.jboss.metadata.web.jboss.JBossWebMetaData;
import org.jboss.metadata.web.spec.ServletMappingMetaData;
import org.jboss.metadata.web.spec.ServletMetaData;
import org.jboss.resteasy.plugins.server.servlet.HttpServlet30Dispatcher;
import org.jboss.resteasy.plugins.server.servlet.ResteasyContextParameters;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Modifier;
import java.net.URLDecoder;


import static org.jboss.as.jaxrs.logging.JaxrsLogger.JAXRS_LOGGER;
import static org.jboss.resteasy.plugins.server.servlet.ResteasyContextParameters.RESTEASY_SCAN;
import static org.jboss.resteasy.plugins.server.servlet.ResteasyContextParameters.RESTEASY_SCAN_PROVIDERS;
import static org.jboss.resteasy.plugins.server.servlet.ResteasyContextParameters.RESTEASY_SCAN_RESOURCES;

/**
 * Process all the Deployment Descriptor data for each servlet-class that is a subClass
 * of Application.  Set the appropriate Resteasy configuration switches.
 *
 * User: rsearls
 * Date: 2/10/17
 */
public class ConfigApplicationClassAsServletUtil {
    private static final DotName DECORATOR = DotName.createSimple("javax.decorator.Decorator");

    protected boolean checkDeclaredApplicationClassAsServlet(JBossWebMetaData webData,
                                                             ClassLoader classLoader,
                                                             final ResteasyDeploymentData resteasyDeploymentData,
                                                             final CompositeIndex index) throws DeploymentUnitProcessingException {

        if (webData.getServlets() != null) {

            for (ServletMetaData servlet : webData.getServlets()) {
                String servletClass = servlet.getServletClass();
                if (servletClass == null)
                    continue;
                Class<?> clazz = null;
                try {
                    clazz = classLoader.loadClass(servletClass);
                } catch (ClassNotFoundException e) {
                    throw new DeploymentUnitProcessingException(e);
                }
                if (Application.class.isAssignableFrom(clazz)) {
                    servlet.setServletClass(HttpServlet30Dispatcher.class.getName());
                    servlet.setAsyncSupported(true);
                    setServletInitParam(servlet, "javax.ws.rs.Application", servletClass);
                    String servletName = servlet.getServletName();
                    ServletMappingMetaData mapping = getServletMappings(webData, servletName);
                    if (mapping == null) {
                        setApplicationPathServletMapping(webData, clazz, servletName, servlet);
                    } else {
                        setServletMappingPrefix(webData, servletName, servlet);
                    }

                    // check and reset global switch only once.
                    if (!resteasyDeploymentData.isDispatcherCreated()) {
                        // Instigate creation of resteasy configuration switches for
                        // found provider and resource classes
                        resteasyDeploymentData.setScanProviders(true);
                        resteasyDeploymentData.setScanResources(true);
                        checkGlobalConfigSwitches(webData, resteasyDeploymentData);
                    }
                    checkApplicationMetaData(clazz, servlet, resteasyDeploymentData, index);

                    // at least 1 App subclass present in web.xml
                    resteasyDeploymentData.setDispatcherCreated(true);
                }
            }
        }

        return resteasyDeploymentData.isDispatcherCreated();
    }

    /**
     * Applies the rules for finding app resource and producer classes and passing them
     * to Resteasy by their proper Configuration switch.
     *
     * @param clazz
     * @param servlet
     * @param resteasyDeploymentData
     * @param index
     */
    protected void checkApplicationMetaData(Class<?> clazz, ServletMetaData servlet,
                                            final ResteasyDeploymentData resteasyDeploymentData,
                                            final CompositeIndex index) {
        try {
            Application appClazz = (Application) clazz.newInstance();
            Set<Class<?>> declClazzs = appClazz.getClasses();
            Set<Object> declSingletons = appClazz.getSingletons();
            StringBuilder resourceSwitchStrBuilder = new StringBuilder();
            StringBuilder providerSwtichStrBuilder = new StringBuilder();

            if (declClazzs.isEmpty() && declClazzs.isEmpty()) {
                processCompositIndex(index, resourceSwitchStrBuilder,
                    providerSwtichStrBuilder, resteasyDeploymentData);
            } else {
                processClazzAndSingltons(declClazzs, declSingletons,
                    resourceSwitchStrBuilder, providerSwtichStrBuilder);
            }


            if (resourceSwitchStrBuilder.length() > 0) {
                String resources = resourceSwitchStrBuilder.toString();
                JAXRS_LOGGER.debugf("Adding JAX-RS resource classes: %s", resources);
                setServletInitParam(servlet, ResteasyContextParameters.RESTEASY_SCANNED_RESOURCES,
                    resources);
            }

            if (providerSwtichStrBuilder.length() > 0) {
                String providers = providerSwtichStrBuilder.toString();
                JAXRS_LOGGER.debugf("Adding JAX-RS provider classes: %s", providers);
                setServletInitParam(servlet, ResteasyContextParameters.RESTEASY_SCANNED_PROVIDERS,
                    providers);
            }

        } catch (Exception e) {
            // todo JAXRS_LOGGER.classAnnotationNotFound("@Provider", e.target());
        }

    }

    /**
     * An Application subclass can declare a set of classes that are to be available
     * to the servlet via methods getClasses and getSingletons.  When these methods
     * return class names, the names prepared to be passed to Resteasy by their proper
     * Configuration switch.
     *
     * @param declClazzs
     * @param declSingletons
     * @param resourceSwitchStrBuilder
     * @param providerSwtichStrBuilder
     */
    private void processClazzAndSingltons(Set<Class<?>> declClazzs,
                                          Set<Object> declSingletons,
                                          StringBuilder resourceSwitchStrBuilder,
                                          StringBuilder providerSwtichStrBuilder) {

        for (Class<?> cClazz : declClazzs) {
            boolean rlist = cClazz.isAnnotationPresent(javax.ws.rs.Path.class);
            if (rlist) {
                //resteasyDeploymentData.getScannedResourceClasses().add(((Class) cClazz).getName());
                appendText(resourceSwitchStrBuilder, ((Class) cClazz).getName());
            }

            boolean plist = cClazz.isAnnotationPresent(javax.ws.rs.ext.Provider.class);
            if (plist) {
                //resteasyDeploymentData.getScannedProviderClasses().add(((Class) cClazz).getName());
                appendText(providerSwtichStrBuilder, ((Class) cClazz).getName());
            }
        }


        for (Object cClazz : declSingletons) {
            boolean rlist = ((Class) cClazz).isAnnotationPresent(javax.ws.rs.Path.class);
            if (rlist) {
                //resteasyDeploymentData.getScannedResourceClasses().add(((Class) cClazz).getName());
                appendText(resourceSwitchStrBuilder, ((Class) cClazz).getName());
            }

            boolean plist = ((Class) cClazz).isAnnotationPresent(javax.ws.rs.ext.Provider.class);
            if (plist) {
                //resteasyDeploymentData.getScannedProviderClasses().add(((Class) cClazz).getName());
                appendText(providerSwtichStrBuilder, ((Class) cClazz).getName());
            }
        }
    }

    /**
     * Lookup in the deployment archive the resource and provider classes to be submitted
     * for the app.  The class names are prepared to be passed to Resteasy by their proper
     * Configuration switch.
     *
     * @param index
     * @param resourceSwitchStrBuilder
     * @param providerSwtichStrBuilder
     * @param resteasyDeploymentData
     */
    private void processCompositIndex(final CompositeIndex index,
                                      StringBuilder resourceSwitchStrBuilder,
                                      StringBuilder providerSwtichStrBuilder,
                                      final ResteasyDeploymentData resteasyDeploymentData) {

        final Set<ClassInfo> pathInterfaces = new HashSet<ClassInfo>();
        List<AnnotationInstance> resources = null;
        List<AnnotationInstance> providers = null;
        if (resteasyDeploymentData.isScanResources()) {
            resources = index.getAnnotations(JaxrsAnnotations.PATH.getDotName());
        }
        if (resteasyDeploymentData.isScanProviders()) {
            providers = index.getAnnotations(JaxrsAnnotations.PROVIDER.getDotName());
        }

        if ((resources == null || resources.isEmpty()) &&
            (providers == null || providers.isEmpty())) {
            return;
        } else {
            if (resources != null) {
                for (AnnotationInstance e : resources) {
                    final ClassInfo info;
                    if (e.target() instanceof ClassInfo) {
                        info = (ClassInfo) e.target();
                    } else if (e.target() instanceof MethodInfo) {
                        //ignore
                        continue;
                    } else {
                        JAXRS_LOGGER.classOrMethodAnnotationNotFound("@Path", e.target());
                        continue;
                    }
                    if(info.annotations().containsKey(DECORATOR)) {
                        //we do not add decorators as resources
                        //we can't pick up on programatically added decorators, but that is such an edge case it should not really matter
                        continue;
                    }
                    if (!Modifier.isInterface(info.flags())) {
                        //resteasyDeploymentData.getScannedResourceClasses().add(info.name().toString());
                        appendText(resourceSwitchStrBuilder, info.name().toString());
                    } else {
                        pathInterfaces.add(info);
                    }
                }


                // look for all implementations of interfaces annotated @Path
                for (final ClassInfo iface : pathInterfaces) {
                    final Set<ClassInfo> implementors = index.getAllKnownImplementors(iface.name());
                    for (final ClassInfo implementor : implementors) {

                        if(implementor.annotations().containsKey(DECORATOR)) {
                            //we do not add decorators as resources
                            //we can't pick up on programatically added decorators, but that is such an edge case it should not really matter
                            continue;
                        }
                        //resteasyDeploymentData.getScannedResourceClasses().add(implementor.name().toString());
                        appendText(resourceSwitchStrBuilder, implementor.name().toString());
                    }
                }
            }
        }

        if (providers != null) {
            for (AnnotationInstance e : providers) {
                if (e.target() instanceof ClassInfo) {
                    ClassInfo info = (ClassInfo) e.target();

                    if(info.annotations().containsKey(DECORATOR)) {
                        //we do not add decorators as providers
                        //we can't pick up on programatically added decorators, but that is such an edge case it should not really matter
                        continue;
                    }
                    if (!Modifier.isInterface(info.flags())) {
                        //resteasyDeploymentData.getScannedProviderClasses().add(info.name().toString());
                        appendText(providerSwtichStrBuilder, info.name().toString());
                    }
                } else {
                    JAXRS_LOGGER.classAnnotationNotFound("@Provider", e.target());
                }
            }
        }
    }

    /**
     * Format for resource and provider switch values.
     *
     * @param sBuilder
     * @param text
     * @return
     */
    private StringBuilder appendText(StringBuilder sBuilder, String text) {
        if (sBuilder.length() > 0) {
            sBuilder.append(",").append(text);
        } else {
            sBuilder.append(text);
        }
        return sBuilder;
    }

    /**
     *
     * @param webData
     * @param clazz
     * @param servletName
     * @param servlet
     */
    protected void setApplicationPathServletMapping(JBossWebMetaData webData,
                                                    Class<?> clazz, String servletName,
                                                    ServletMetaData servlet) {
        try {
            //no mappings, add our own
            List<String> patterns = new ArrayList<String>();
            //for some reason the spec requires this to be decoded
            String pathValue = URLDecoder.decode(clazz.getAnnotation(ApplicationPath.class).value().trim(), "UTF-8");
            if (!pathValue.startsWith("/")) {
                pathValue = "/" + pathValue;
            }
            String prefix = pathValue;
            if (pathValue.endsWith("/")) {
                pathValue += "*";
            } else {
                pathValue += "/*";
            }
            patterns.add(pathValue);
            setServletInitParam(servlet, "resteasy.servlet.mapping.prefix", prefix);
            ServletMappingMetaData mappingData = new ServletMappingMetaData();
            mappingData.setServletName(servletName);
            mappingData.setUrlPatterns(patterns);
            if (webData.getServletMappings() == null) {
                webData.setServletMappings(new ArrayList<ServletMappingMetaData>());
            }
            webData.getServletMappings().add(mappingData);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     *
     * @param webdata
     * @param servletName
     * @return
     */
    protected ServletMappingMetaData getServletMappings(JBossWebMetaData webdata, String servletName) {
        List<ServletMappingMetaData> mappings = webdata.getServletMappings();

        if (mappings != null && !mappings.isEmpty()) {
            for (ServletMappingMetaData mapping : mappings) {
                if (mapping.getServletName().equals(servletName)) {
                    return mapping;
                }
            }
        }
        return null;
    }

    /**
     * Extract and set the resteasy configuration switch, resteasy.servlet.mapping.prefix
     *
     * @param webdata
     * @param servletName
     * @param servlet
     */
    private void setServletMappingPrefix(JBossWebMetaData webdata, String servletName, ServletMetaData servlet) {
        final List<ServletMappingMetaData> mappings = webdata.getServletMappings();
        if (mappings != null && !mappings.isEmpty()) {
            boolean mappingSet = false;
            for (final ServletMappingMetaData mapping : mappings) {
                if (mapping.getServletName().equals(servletName)) {
                    if (mapping.getUrlPatterns() != null) {
                        for (String pattern : mapping.getUrlPatterns()) {
                            if (mappingSet) {
                                JAXRS_LOGGER.moreThanOneServletMapping(servletName, pattern);
                            } else {
                                mappingSet = true;
                                String realPattern = pattern;
                                if (realPattern.endsWith("*")) {
                                    realPattern = realPattern.substring(0, realPattern.length() - 1);
                                }
                                setServletInitParam(servlet, "resteasy.servlet.mapping.prefix", realPattern);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     *
     * @param servlet
     * @param name
     * @param value
     */
    protected void setServletInitParam(ServletMetaData servlet, String name, String value) {
        ParamValueMetaData param = new ParamValueMetaData();
        param.setParamName(name);
        param.setParamValue(value);
        List<ParamValueMetaData> params = servlet.getInitParam();
        if (params == null) {
            params = new ArrayList<ParamValueMetaData>();
            servlet.setInitParam(params);
        }
        params.add(param);
    }

    /**
     *
     * @param webdata
     * @param resteasyDeploymentData
     * @throws DeploymentUnitProcessingException
     */
    private void checkGlobalConfigSwitches(final JBossWebMetaData webdata,
                                           final ResteasyDeploymentData resteasyDeploymentData)
        throws DeploymentUnitProcessingException {

        List<ParamValueMetaData> contextParams = webdata.getContextParams();
        if (contextParams != null && !contextParams.isEmpty()) {
            for (ParamValueMetaData param : contextParams) {
                if (param.getParamName().equals(RESTEASY_SCAN)) {
                    resteasyDeploymentData.setScanAll(valueOf(RESTEASY_SCAN, param.getParamValue()));
                } else if (param.getParamName().equals(ResteasyContextParameters.RESTEASY_SCAN_PROVIDERS)) {
                    resteasyDeploymentData.setScanProviders(valueOf(RESTEASY_SCAN_PROVIDERS, param.getParamValue()));
                } else if (param.getParamName().equals(RESTEASY_SCAN_RESOURCES)) {
                    resteasyDeploymentData.setScanResources(valueOf(RESTEASY_SCAN_RESOURCES, param.getParamValue()));
                } else if (param.getParamName().equals(ResteasyContextParameters.RESTEASY_UNWRAPPED_EXCEPTIONS)) {
                    resteasyDeploymentData.setUnwrappedExceptionsParameterSet(true);
                }
            }
        }
    }

    /**
     *
     * @param paramName
     * @param value
     * @return
     * @throws DeploymentUnitProcessingException
     */
    private boolean valueOf(String paramName, String value) throws DeploymentUnitProcessingException {
        if (value == null) {
            throw JaxrsLogger.JAXRS_LOGGER.invalidParamValue(paramName, value);
        }
        if (value.toLowerCase(Locale.ENGLISH).equals("true")) {
            return true;
        } else if (value.toLowerCase(Locale.ENGLISH).equals("false")) {
            return false;
        } else {
            throw JaxrsLogger.JAXRS_LOGGER.invalidParamValue(paramName, value);
        }
    }
}
