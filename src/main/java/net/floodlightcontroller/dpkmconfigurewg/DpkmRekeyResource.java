package net.floodlightcontroller.dpkmconfigurewg;

import org.projectfloodlight.openflow.types.DatapathId;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DpkmRekeyResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	@Post
	public String rekey(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = DpkmConfigureWGResource.jsonToDpkmSwitch(fmJson);
		if (node == null) {
			return "{\"status\" : \"Error! Could not parse switch info, see log for details.\"}";
		}
		String status = null;
		configureWG.rekey(node.dpid, node.cryptoperiod);
		status = "DPKM_SET_KEY message sent to switch.";
		return ("{\"status\" : \"" + status + "\"}");
	}
}
