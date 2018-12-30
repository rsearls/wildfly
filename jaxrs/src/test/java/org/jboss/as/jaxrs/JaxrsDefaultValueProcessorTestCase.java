package org.jboss.as.jaxrs;

import org.jboss.as.jaxrs.deployment.JaxrsDefaultValueProcessor;
import org.jboss.as.jaxrs.rsources.DummyParamConverterProvider;
import org.jboss.as.jaxrs.rsources.NullParamConverterParamDummyConverter;
import org.jboss.as.jaxrs.rsources.OneParamResource;
import org.jboss.as.jaxrs.rsources.ParamConverterLazyParamDummyConverter;
import org.jboss.as.jaxrs.rsources.ParamConverterParamDummyConverter;
import org.jboss.as.jaxrs.rsources.SecondParamResource;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class JaxrsDefaultValueProcessorTestCase {
    JaxrsDefaultValueProcessor jca = new JaxrsDefaultValueProcessor();

    private List<String> resources = new ArrayList<>();
    private List<String> providers = new ArrayList<>();

    /**
     * A ParamConverter is provided for ParamDummy.  This should run
     * without error.
     */
    @Test
    public void successfulComponentsTest() {
        resources.clear();
        resources.add(OneParamResource.class.getName());
        providers.clear();
        providers.add(DummyParamConverterProvider.class.getName());
        providers.add(ParamConverterLazyParamDummyConverter.class.getName());
        providers.add(ParamConverterParamDummyConverter.class.getName());
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        try {
            jca.processClasses(providers, resources, classLoader);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * No ParamConverter is provided for class SecondDummy.  This should
     * cause an error to be reported.
     */
    @Test
    public void missingParamConvertorTest() {
        resources.clear();
        resources.add(SecondParamResource.class.getName());
        providers.clear();
        providers.add(ParamConverterParamDummyConverter.class.getName());
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        try {
            jca.processClasses(providers, resources, classLoader);
            Assert.fail("test failed to throw expected exception");
        } catch (Exception e) {
           // success, an exception was thrown
        }
    }

    /**
     * ParamConverter returns null.  This is an error that is reported.
     */
    @Test
    public void nullParamConvertorTest() {
        resources.clear();
        resources.add(OneParamResource.class.getName());
        providers.clear();
        providers.add(NullParamConverterParamDummyConverter.class.getName());
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        try {
            jca.processClasses(providers, resources, classLoader);
            Assert.fail("test failed to throw expected exception");
        } catch (Exception e) {
            // success, an exception was thrown
        }
    }
}
