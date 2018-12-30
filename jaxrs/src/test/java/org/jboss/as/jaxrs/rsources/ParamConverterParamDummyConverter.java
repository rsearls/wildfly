package org.jboss.as.jaxrs.rsources;

import javax.ws.rs.ext.ParamConverter;

public class ParamConverterParamDummyConverter implements ParamConverter<ParamDummy>  {
    public ParamDummy fromString(String str) {
        ParamDummy pojo = new ParamDummy();
        pojo.setValue(Integer.valueOf(str));
        return pojo;
    }

    public String toString(ParamDummy value) {
        return value.getValue().toString();
    }
}
