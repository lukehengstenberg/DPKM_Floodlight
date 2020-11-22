package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * REST API for rekeying a switch upon expiry of its cryptoperiod. </br>
 * Takes json data from UI and deserializes, executing rekeying function.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmRekeyResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	
	/** 
	 * Rekey's switch matching the given json by running the configuration procedure.</br>
	 * Deserializes to get switch information, sending SET_KEY message on success.
	 * @param fmJson Json structure containing switch information.  
	 * @return String status either success or error. 
	 */
	@Post
	public synchronized String rekey(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = DpkmConfigureWGResource.jsonToDpkmSwitch(fmJson);
		String status = null;
		if (node == null) {
			status = "Error! Could not parse switch info, see log for details.";
			return ("{\"status\" : \"" + status + "\"}");
		}
		if(configureWG.checkCompromised(node.getDpId())) {
			status = "Error! Cannot rekey a compromised switch.";
			return ("{\"status\" : \"" + status + "\"}");
		}
		configureWG.rekey(node.getDpId(), node.getCryptoperiod());
		status = "DPKM_SET_KEY message sent to switch.";
		return ("{\"status\" : \"" + status + "\"}");
	}
}
