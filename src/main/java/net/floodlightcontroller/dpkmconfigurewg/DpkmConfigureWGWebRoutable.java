package net.floodlightcontroller.dpkmconfigurewg;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;
 
import net.floodlightcontroller.restserver.RestletRoutable;

public class DpkmConfigureWGWebRoutable implements RestletRoutable {
	@Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/retrieve/json", DpkmConfigureWGResource.class);
        router.attach("/configure/json", DpkmConfigureWGResource.class);
        router.attach("/delete/key/json", DpkmConfigureWGResource.class);
        router.attach("/retrieve/peers/json", DpkmManagePeerResource.class);
        router.attach("/add/peer/json", DpkmManagePeerResource.class);
        router.attach("/delete/peer/json", DpkmManagePeerResource.class);
        router.attach("/start/json", DpkmStartCommunicationResource.class);
        router.attach("/rekey/json", DpkmRekeyResource.class);
        return router;
    }
 
    @Override
    public String basePath() {
        return "/wm/dpkm";
    }
}
