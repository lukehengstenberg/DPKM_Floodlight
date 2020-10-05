package net.floodlightcontroller.dpkmconfigurewg;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * REST API for rekeying a switch upon expiry of its cryptoperiod. <br>
 * Takes json data from UI and deserializes, executing rekeying function.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmRekeyResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	/** 
	 * Rekey's switch matching the given json by running the configuration procedure.
	 * Deserializes to get switch information, sending SET_KEY message on success.
	 * @param fmJson Json structure containing switch information.  
	 * @return String status either success or error. 
	 */
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
