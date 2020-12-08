package net.floodlightcontroller.dpkmconfigurewg;

import java.util.Iterator;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * REST API for ending communication between two connected peers. </br>
 * Takes json data from UI and deserializes, executing endCommunication to 
 * terminate all or WG only communication depending on the top level preference.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmEndCommunicationResource extends ServerResource {
	protected static Logger log = 
			LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	/** 
	 * Ends communication for connection with matching peer information in json.</br>
	 * Deserializes to get both peer switch information and end type.</br>
	 * Either removes flow entirely or modifies flow to continue unencrypted.
	 * @param fmJson Json structure containing peer information.  
	 * @return String status either success or error. 
	 * @see DpkmManagePeerResource#jsonToDpkmPeer(String)
	 * @see DpkmConfigureWG#getPeers()
	 * @see DpkmConfigureWG#checkConnected(String, String, String)
	 * @see DpkmConfigureWG#endCommunication(String, String, String)
	 */
	@Post
    public String end(String fmJson) {
    	IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmPeers peers = DpkmManagePeerResource.jsonToDpkmPeer(fmJson);
		String status = null;
		if (peers == null) {
			status = "Error! Could not parse switch info, see log for details.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		boolean exists = false;
		Iterator<DpkmPeers> iter = configureWG.getPeers().iterator();
		while (iter.hasNext()) {
			DpkmPeers p = iter.next();
			if (p.cid == peers.cid) {
				peers.dpidA = p.dpidA;
				peers.dpidB = p.dpidB;
				peers.ipv4AddrA = p.ipv4AddrA;
				peers.ipv4AddrB = p.ipv4AddrB;
				exists = true;
				break;
			}
		}
		if (configureWG.checkConnected(peers.ipv4AddrA, peers.ipv4AddrB, 
				"COMMUNICATING") == 0) {
			status = "Error! These peers are not communicating.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		else if (!exists) {
			status = "Error! No peer connection with this id exists.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		} else {
			configureWG.endCommunication(peers.dpidA, peers.dpidB, peers.status);
			status = "All communication ended between peers.";
			if(peers.status.equalsIgnoreCase("endWG")) {
				status = "Wireguard communication ended between peers.";
			}
			return ("{\"status\" : \"" + status + "\"}");
		}
    }
}
