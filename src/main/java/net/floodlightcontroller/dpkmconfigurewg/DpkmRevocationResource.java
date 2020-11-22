package net.floodlightcontroller.dpkmconfigurewg;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * REST API for carrying out the revocation procedure with a compromised switch. </br>
 * Utility is decided by the administrator either reconfiguring the switch with
 * new public/private keys or terminating the switch entirely. </br>
 * Takes json data from UI and deserializes, executing corresponding function.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmRevocationResource extends ServerResource{
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	/** 
	 * Revoke the keys of the switch with matching info in the given fmJson.</br>
	 * Calls revoke with the dpid and type of revocation to carry out.
	 * @param fmJson Json structure containing switch information.  
	 * @return String status either success or error.  
	 */
	@Post
	public String revoke(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = DpkmConfigureWGResource.jsonToDpkmSwitch(fmJson);
		String status = null;
		if (node == null) {
			status = "Error! Could not parse switch info, see log for details.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		configureWG.revoke(node.getDpId(), node.getStatus());
		status = "Node has been fully terminated.";
		if(node.getStatus().equalsIgnoreCase("reConf")) {
			status = "Node has been reconfigured.";
		}
		return ("{\"status\" : \"" + status + "\"}");
		
	}
}
