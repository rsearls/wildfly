package org.jboss.as.jaxrs.deployment;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.List;

import org.jboss.as.ee.structure.DeploymentType;
import org.jboss.as.ee.structure.DeploymentTypeMarker;
import org.jboss.as.jaxrs.JaxrsAnnotations;
import org.jboss.as.server.deployment.Attachments;
import org.jboss.as.server.deployment.DeploymentPhaseContext;
import org.jboss.as.server.deployment.DeploymentUnit;
import org.jboss.as.server.deployment.DeploymentUnitProcessingException;
import org.jboss.as.server.deployment.DeploymentUnitProcessor;
import org.jboss.as.server.deployment.annotation.CompositeIndex;
import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.modules.Module;
import org.jboss.as.jaxrs.logging.JaxrsLogger;
import static org.jboss.as.jaxrs.logging.JaxrsLogger.JAXRS_LOGGER;
import org.jboss.jandex.MethodInfo;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.ext.ParamConverter;

/**
 * Class addresses RESTEASY-2062.  During the deployment process
 * report issues when setting values for @DefaultValue. JAX-RS
 * spec chapter 3.
 */
public class JaxrsDefaultValueProcessor implements DeploymentUnitProcessor {
    List<String> resources = new ArrayList<String>();
    List<String> providers = new ArrayList<String>();

    @Override
    public void undeploy(DeploymentUnit context) {
        // no-op
    }

    @Override
    public void deploy(DeploymentPhaseContext phaseContext)
            throws DeploymentUnitProcessingException {

        final DeploymentUnit deploymentUnit = phaseContext.getDeploymentUnit();

        if (!JaxrsDeploymentMarker.isJaxrsDeployment(deploymentUnit)) {
            return;
        }

        if (!DeploymentTypeMarker.isType(DeploymentType.WAR, deploymentUnit)) {
            return;
        }

        final Module module = deploymentUnit.getAttachment(Attachments.MODULE);
        final ResteasyDeploymentData resteasyDeploymentData = deploymentUnit.getAttachment(
                JaxrsAttachments.RESTEASY_DEPLOYMENT_DATA);

        if (resteasyDeploymentData == null) {
            return;
        }

        scan(deploymentUnit, resteasyDeploymentData, module.getClassLoader());
        processClasses(providers, resources, module.getClassLoader());
    }

    /**
     * This method allows the unit test to test this part of the code.
     * @param providers
     * @param resources
     * @param classLoader
     * @throws DeploymentUnitProcessingException
     */
    public void processClasses(final List<String> providers,
                                  final List<String> resources,
                                  final ClassLoader classLoader)
            throws DeploymentUnitProcessingException  {

        HashMap<String, List<ParamConverterData>> paramConverterDataMap =
                analyzeProviderClasses(providers, classLoader);

        List<AnnotatedParameterData> annotationParameterDataList =
                analyzeResourceClasses(resources, classLoader);

        validationCheck(paramConverterDataMap, annotationParameterDataList);
    }

    private void scan (final DeploymentUnit du, final ResteasyDeploymentData resteasyDeploymentData,
                       final ClassLoader classLoader) {

        final DotName DECORATOR = DotName.createSimple("javax.decorator.Decorator");
        final String ORG_APACHE_CXF = "org.apache.cxf";
        final CompositeIndex index = du.getAttachment(
                Attachments.COMPOSITE_ANNOTATION_INDEX);

        //List<AnnotationInstance> resourcesList = index.getAnnotations(
        //        JaxrsAnnotations.PATH.getDotName());
        //List<AnnotationInstance> providersList = index.getAnnotations(
        //        JaxrsAnnotations.PROVIDER.getDotName());
        Set<ClassInfo> paramConvertersSet = index.getKnownDirectImplementors(
                DotName.createSimple("javax.ws.rs.ext.ParamConverter"));

        if (paramConvertersSet != null) {
            for (ClassInfo info : paramConvertersSet) {
                if(info.name().toString().startsWith(ORG_APACHE_CXF)) {
                    continue;
                }
                if(info.annotations().containsKey(DECORATOR)) {
                    continue;
                }
                if (!Modifier.isInterface(info.flags())) {
                    resources.add(info.name().toString());
                }
            }
        }

        if (resteasyDeploymentData.getScannedResourceClasses() == null ||
                resteasyDeploymentData.getScannedResourceClasses().isEmpty())
        {
            List<AnnotationInstance> resourcesList = index.getAnnotations(
                    JaxrsAnnotations.PATH.getDotName());
            if (resourcesList != null) {
                for (AnnotationInstance e : resourcesList) {
                    final ClassInfo info;
                    if (e.target() instanceof ClassInfo) {
                        info = (ClassInfo) e.target();
                    } else if (e.target() instanceof MethodInfo) {
                        continue;
                    } else {
                        JAXRS_LOGGER.classOrMethodAnnotationNotFound("@Path", e.target());
                        continue;
                    }
                    if(info.name().toString().startsWith(ORG_APACHE_CXF)) {
                        continue;
                    }
                    if(info.annotations().containsKey(DECORATOR)) {
                        continue;
                    }
                    if (!Modifier.isInterface(info.flags())) {
                        resources.add(info.name().toString());
                    }
                }
            }

        }
        else {
            resources.addAll(resteasyDeploymentData.getScannedResourceClasses());
        }
        /******
        if (resourcesList != null) {
            for (AnnotationInstance e : resourcesList) {
                final ClassInfo info;
                if (e.target() instanceof ClassInfo) {
                    info = (ClassInfo) e.target();
                } else if (e.target() instanceof MethodInfo) {
                    continue;
                } else {
                    JAXRS_LOGGER.classOrMethodAnnotationNotFound("@Path", e.target());
                    continue;
                }
                if(info.name().toString().startsWith(ORG_APACHE_CXF)) {
                    continue;
                }
                if(info.annotations().containsKey(DECORATOR)) {
                    continue;
                }
                if (!Modifier.isInterface(info.flags())) {
                    resources.add(info.name().toString());
                }
            }
        }
*********/
        if (resteasyDeploymentData.getScannedProviderClasses() == null ||
                resteasyDeploymentData.getScannedProviderClasses().isEmpty())
        {
            List<AnnotationInstance> providersList = index.getAnnotations(
                    JaxrsAnnotations.PROVIDER.getDotName());

            if (providersList != null) {
                for (AnnotationInstance e : providersList) {
                    if (e.target() instanceof ClassInfo) {
                        ClassInfo info = (ClassInfo) e.target();

                        if(info.name().toString().startsWith(ORG_APACHE_CXF)) {
                            continue;
                        }
                        if(info.annotations().containsKey(DECORATOR)) {
                            continue;
                        }
                        if (!Modifier.isInterface(info.flags())) {
                            providers.add(info.name().toString());
                        }
                    } else {
                        JAXRS_LOGGER.classAnnotationNotFound("@Provider", e.target());
                    }
                }
            }
        }
        else {
            providers.addAll(resteasyDeploymentData.getScannedProviderClasses());
        }
        /****
        if (providersList != null) {
            for (AnnotationInstance e : providersList) {
                if (e.target() instanceof ClassInfo) {
                    ClassInfo info = (ClassInfo) e.target();

                    if(info.name().toString().startsWith(ORG_APACHE_CXF)) {
                        continue;
                    }
                    if(info.annotations().containsKey(DECORATOR)) {
                        continue;
                    }
                    if (!Modifier.isInterface(info.flags())) {
                        providers.add(info.name().toString());
                    }
                } else {
                    JAXRS_LOGGER.classAnnotationNotFound("@Provider", e.target());
                }
            }
        }
****/
    }
    /**
     * Collect all ParamConverter implementations found.
     *
     * @param providerList
     * @param classLoader
     * @return
     */
    private HashMap<String, List<ParamConverterData>> analyzeProviderClasses(
            List<String> providerList, ClassLoader classLoader) {

        HashMap<String, List<ParamConverterData>> paramConverterDataMap =
                new HashMap<>();

        for (String provider : providerList) {

            try {
                Class providerClazz = classLoader.loadClass(provider);
                Object tmpObj = getClassInstance(providerClazz);

                if (tmpObj != null) {
                    if (tmpObj instanceof ParamConverter) {
                        Annotation annotation = providerClazz.getAnnotation(
                                ParamConverter.Lazy.class);
                        if (annotation == null) {
                            Method method = providerClazz.getMethod("fromString", String.class);
                            Class rtnType = method.getReturnType();
                            List<ParamConverterData> value = paramConverterDataMap.get(rtnType.getName());
                            if (value == null) {
                                ArrayList<ParamConverterData> paramConverterDataList = new ArrayList<>();
                                paramConverterDataList.add(
                                        new ParamConverterData(method, (ParamConverter) tmpObj));
                                paramConverterDataMap.put(rtnType.getName(), paramConverterDataList);
                            } else {
                                value.add(new ParamConverterData(method, (ParamConverter) tmpObj));
                            }
                        }
                    }
                }
            } catch (NoSuchMethodException nsme) {
                // no-op
            } catch (ClassNotFoundException e) {
                // no-op
            }
        }
        return paramConverterDataMap;
    }

    /**
     * Identify all method input parameters annotated with @DefaultValue.  Collect
     * the default value and the parameter class type.
     *
     * @param resourceList
     * @param classLoader
     * @return
     */
    private List<AnnotatedParameterData> analyzeResourceClasses(List<String> resourceList,
                                                         ClassLoader classLoader) {

        ArrayList<AnnotatedParameterData> annotationParameterDataList =
                new ArrayList<>();

        for (String resource : resourceList) {
            try {
                Class resourceClazz = classLoader.loadClass(resource);
                Object tmpObj = getClassInstance(resourceClazz);

                if (tmpObj != null) {
                    Method[] methods = resourceClazz.getMethods();

                    // check each method for the "DefaultValue" annotation on parameter
                    for (int i = 0; i < methods.length; i++) {
                        Method tmpM = methods[i];
                        Class[] parameterClazzes = tmpM.getParameterTypes();
                        Annotation[][] paramAnns = tmpM.getParameterAnnotations();

                        for (int r = 0; r < paramAnns.length; r++) {
                            for (int c = 0; c < paramAnns[r].length; c++) {
                                if (paramAnns[r][c] instanceof DefaultValue) {
                                    DefaultValue defVal = (DefaultValue) paramAnns[r][c];
                                    annotationParameterDataList.add(
                                            new AnnotatedParameterData(tmpM, r,
                                                    parameterClazzes[r], defVal));
                                }
                            }
                        }
                    }
                }
            } catch (ClassNotFoundException e) {
                // no-op
            }
        }
        return annotationParameterDataList;
    }

    /**
     * Verify there is a ParamConverter class for each @DefaultValue parameter
     * type and the default value can be set without error.
     *
     * @param paramConverterDataMap
     * @param annotationParameterDataList
     */
    private void validationCheck(HashMap<String,
            List<ParamConverterData>> paramConverterDataMap,
            List<AnnotatedParameterData> annotationParameterDataList)
            throws DeploymentUnitProcessingException {

        for(AnnotatedParameterData annParam : annotationParameterDataList) {
            String name = annParam.getParameterClass().getName();
            List<ParamConverterData> paramConverterDataList =
                    paramConverterDataMap.get(name);
            if (paramConverterDataList == null) {
                throw JaxrsLogger.JAXRS_LOGGER.missingParamConvertor(name,
                        annParam.getParamPosition() +1, annParam.getMethod().toString());
            } else {
                // check acceptance of default value
                for (ParamConverterData pConverter : paramConverterDataList) {
                    pConverter.invokeMethod(annParam);
                }
            }
        }
    }

    private Object getClassInstance(Class resourceClazz) {
        Object tmpObj = null;
        try {
            Constructor providerConstructor = resourceClazz.getConstructor();
            tmpObj = providerConstructor.newInstance();
        } catch (InstantiationException ie) {
            // no-op
        } catch (IllegalAccessException iae) {
            // no-op
        } catch (InvocationTargetException ite) {
            // no-op
        } catch (NoSuchMethodException nsme) {
            // no-op
        }
        return tmpObj;
    }


    private class AnnotatedParameterData {
        private Method method;
        private int paramPosition = 0;
        private Class<?> parameterClass;
        private DefaultValue defVal;

        public AnnotatedParameterData (Method method,
                                        int paramPosition, Class<?> parameterClass,
                                        DefaultValue defVal) {
            this.method = method;
            this.paramPosition = paramPosition;
            this.parameterClass = parameterClass;
            this.defVal = defVal;
        }

        public Method getMethod() {
            return method;
        }
        public int getParamPosition() {
            return paramPosition;
        }
        public Class<?> getParameterClass() {
            return parameterClass;
        }
        public DefaultValue getDefaultValue() {
            return defVal;
        }
    }

    private class ParamConverterData {
        private Method method;
        private ParamConverter paramConverter;

        public ParamConverterData(Method method, ParamConverter paramConverter){
            this.method = method;
            this.paramConverter = paramConverter;
        }

        public void invokeMethod(AnnotatedParameterData annParam)
                throws DeploymentUnitProcessingException {

            String arg = annParam.getDefaultValue().value();
            try {
                Object obj = method.invoke(paramConverter, arg);
                if (obj == null) {
                    throw JAXRS_LOGGER.nullReturnValue(paramConverter.getClass().getName(),
                            annParam.getParamPosition() +1, annParam.getMethod().toString());
                }
            } catch (Exception e) {
                throw JAXRS_LOGGER.invalidParamConversion(paramConverter.getClass().getName(),
                        annParam.getParamPosition() +1, annParam.getMethod().toString(),
                        e.getCause().toString());
            }
        }
    }
}
