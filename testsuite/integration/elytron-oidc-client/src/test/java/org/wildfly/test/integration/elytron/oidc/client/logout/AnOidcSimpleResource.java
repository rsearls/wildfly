package org.wildfly.test.integration.elytron.oidc.client.logout;

import java.util.List;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MultivaluedMap;

@Path("/")
public class AnOidcSimpleResource {
    // The variables declared below are for the convenience of
    // configuring the test environment.
    public static final String frontChannelEndpointPath = "/frontchannel";
    public static final String backChannelEndpointPath = "/backchannel";
    public static final String rpInitiatedEndpointPath = "/logout";

    @GET
    @Path("frontchannel")
    @Produces("text/plain")
    @Consumes("text/plain")
    public String frontLogout(String s) {
        return "frontchannel Logout complete";
    }

    @POST
    @Path("backchannel")
    public String simpleBackChannel(@QueryParam("name") String name){
        new Throwable("simpleBackChannel ENTERED").printStackTrace();  // rls debug
        return "backchannel complete";
    }

    @POST
    @Path("backchannel-with-form")
    @Consumes("application/x-www-form-urlencoded")
    public void backChannelSignOff(MultivaluedMap<String, String> form) {

        StringBuilder sb = new StringBuilder();
        sb.append("## backChannelSignOff   form size: " + form.size() + "/n");

        for (String key : form.keySet()) {
            List<String> vList = form.get(key);
            sb.append("key: " + key + " [ ");
            for (String value : vList) {
                sb.append(value+", ");
            }
            sb.append("]/n");
        }
        new Throwable(sb.toString()).printStackTrace();  // rls debug
    }

    @POST
    @Path("logout")
    @Produces("text/plain")
    @Consumes("text/plain")
    public String backLogout(String s) {
        return "backLogout";
    }

    @GET
    @Path("ping")
    @Produces("text/plain")
    public String ping() {
        return "pong";
    }

}
