package net.floodlightcontroller.dpkmconfigurewg;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

/** 
 * REST API for compromising a switch to simulate the behaviour of some security
 * system and begin the revocation procedure. </br>
 * Takes json data from UI and deserializes, executing corresponding function.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmCompromiseNodeResource extends ServerResource {
	
	/** 
	 * Compromise the switch with matching info in the given fmJson. </br>
	 * Calls compromiseNode with the id which ends all communication with the
	 * switch and sets it as "COMPROMISED".
	 * @param fmJson Json structure containing switch information.  
	 * @return String status either success or error. 
	 */
	@Post
	public String compromise(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = DpkmConfigureWGResource.jsonToDpkmSwitch(fmJson);
		if (node == null) {
			return "{\"status\" : \"Error! Could not parse switch info, see log for details.\"}";
		}
		String status = null;
		configureWG.compromiseNode(node.id);
		status = "Node has been compromised.";
		return ("{\"status\" : \"" + status + "\"}");
	}
}
