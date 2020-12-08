package net.floodlightcontroller.dpkmconfigurewg;

import java.util.Iterator;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * REST API for starting communication between two connected peers. </br>
 * Takes json data from UI and deserializes, executing startCommunication function.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmStartCommunicationResource extends ServerResource {
	protected static Logger log = 
			LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	/** 
	 * Starts communication for connection matching peer information in json.</br>
	 * Deserializes to get both peer switch information, sending FLOW_ADD messages 
	 * on success.
	 * @param fmJson Json structure containing peer information.  
	 * @return String status either success or error.
	 * @see DpkmManagePeerResource#jsonToDpkmPeer(String)
	 * @see DpkmConfigureWG#getPeers()
	 * @see DpkmConfigureWG#checkConnected(String, String, String)
	 * @see DpkmConfigureWG#startCommunication(String, String) 
	 */
	@Post
    public String start(String fmJson) {
    	IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmPeers peers = DpkmManagePeerResource.jsonToDpkmPeer(fmJson);
		String status = null;
		if (peers == null) {
			status = "Error! Could not parse switch info, see log for details.";
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
				"COMMUNICATING") > 0) {
			status = "Error! These peers are already communicating.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		else if (!exists) {
			status = "Error! No peer connection with this id exists.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		} else {
			configureWG.startCommunication(peers.dpidA, peers.dpidB);
			status = "Peers added to flow table, directing traffic through WG port.";
			return ("{\"status\" : \"" + status + "\"}");
		}
    }
}
