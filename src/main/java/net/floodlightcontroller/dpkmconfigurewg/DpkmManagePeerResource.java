package net.floodlightcontroller.dpkmconfigurewg;

import java.util.List;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DpkmManagePeerResource extends ServerResource{
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
    @Get("json")
    public List<DpkmPeers> retrieve() {
    	IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
    	return configureWG.getPeers();
    }
	
}
