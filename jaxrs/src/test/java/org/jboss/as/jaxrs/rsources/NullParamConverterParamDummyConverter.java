package org.jboss.as.jaxrs.rsources;

import javax.ws.rs.ext.ParamConverter;

public class NullParamConverterParamDummyConverter  implements ParamConverter<ParamDummy>  {
    public ParamDummy fromString(String str) {
        return null;
    }

    public String toString(ParamDummy value) {
        return value.getValue().toString();
    }
}
