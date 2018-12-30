package org.jboss.as.jaxrs.rsources;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.MatrixParam;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

@Path("/one")
public class OneParamResource {
    @GET
    public void testQueryParam(@DefaultValue("101")
                               @QueryParam("111") ParamDummy param) {
        ParamDummy xparam = param;
    }

    @GET
    public void testMultiParams (
            @QueryParam("120") @DefaultValue("12") ParamDummy param,
            @MatrixParam("130") @DefaultValue("13") ParamDummy mp,
            @DefaultValue("140") @HeaderParam("14") ParamDummy hp) {

    }
}
