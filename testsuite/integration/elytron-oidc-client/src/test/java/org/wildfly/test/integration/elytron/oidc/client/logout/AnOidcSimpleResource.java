package org.wildfly.test.integration.elytron.oidc.client.logout;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

@Path("/")
public class AnOidcSimpleResource {

    @GET
    @Path("frontchannel")
    @Produces("text/plain")
    @Consumes("text/plain")
    public String frontLogout(String s) {
        return "frontchannel Logout complete";
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
