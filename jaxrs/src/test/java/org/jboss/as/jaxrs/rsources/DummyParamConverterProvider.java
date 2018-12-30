package org.jboss.as.jaxrs.rsources;

import javax.ws.rs.ext.ParamConverter;
import javax.ws.rs.ext.ParamConverterProvider;
import javax.ws.rs.ext.Provider;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

@Provider
public class DummyParamConverterProvider implements ParamConverterProvider {
    @Override
    public <T> ParamConverter<T> getConverter(Class<T> rawType, Type genericType,
                                              Annotation[] annotations) {
        if (rawType.getName().equals(ParamDummy.class.getName())) {
            return new ParamConverter<T>() {
                @Override
                public T fromString(String value) {
                    ParamDummy param = new ParamDummy();
                    param.setValue(Integer.valueOf(value));
                    return (T) param;
                }

                @Override
                public String toString(T value) {
                    return value.toString();
                }
            };
        }
        return null;
    }
}
