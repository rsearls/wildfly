package org.jboss.as.jaxrs.rsources;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

@Path("/second")
public class SecondParamResource {
    @GET
    public void secondDummyParam(@DefaultValue("202")
                                 @QueryParam("222") SecondDummy param) {
        // no-op
        // There is no ParamConverter provided causing this test to fail
    }
}
