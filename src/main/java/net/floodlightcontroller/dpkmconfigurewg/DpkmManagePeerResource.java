package net.floodlightcontroller.dpkmconfigurewg;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;


/** 
 * REST APIs for retrieving peers and adding/deleting a peer connection. <br>
 * Takes json data from UI and deserializes, executing corresponding function.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmManagePeerResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	/** 
	 * Returns a full list of peer connections from the db in json format. 
	 * @return List<DpkmPeers> List of WG peers from db. 
	 */
    @Get("json")
    public List<DpkmPeers> retrieve() {
    	IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
    	return configureWG.getPeers();
    }
	
    /** 
	 * Adds a new peer connection for the switch information in the given json.
	 * Deserializes to get both peer switch information, sending ADD_PEER message on success.
	 * @param fmJson Json structure containing switch information.  
	 * @return String status either success or error. 
	 */
    @Post
    public String add(String fmJson) {
    	IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmPeers peers = jsonToDpkmPeer(fmJson);
		if (peers == null) {
			return "{\"status\" : \"Error! Could not parse switch info, see log for details.\"}";
		}
		String status = null;
		if (configureWG.checkConnected(peers.ipv4AddrA, peers.ipv4AddrB, 0) > 0) {
			status = "Error! A peer connection with this switch already exists.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		else if (configureWG.checkConnected(peers.ipv4AddrA, peers.ipv4AddrB, 0) == -1) {
			status = "Error! Failed to access the database.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		} else {
			// Send add peer message to one switch, add second after status response.  
			configureWG.sendAddPeerMessage(peers.dpidA, peers.dpidB);
			status = "DPKM_ADD_PEER message sent to switch.";

			return ("{\"status\" : \"" + status + "\"}");
		}
    }
    
    /** 
	 * Deletes a peer connection for db record matching the id in the json.
	 * Deserializes to get id, finds db record, sending DELETE_PEER message on success.
	 * @param fmJson Json structure containing peer information.  
	 * @return String status either success or error. 
	 */
    @Delete
    public String delete(String fmJson) {
    	IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
    	DpkmPeers peers = jsonToDpkmPeer(fmJson);
    	if (peers == null) {
			return "{\"status\" : \"Error! Could not parse switch info, see log for details.\"}";
		}
		String status = null;
		boolean exists = false;
		Iterator<DpkmPeers> iter = configureWG.getPeers().iterator();
		// Loop through peers to find switch information. 
		while (iter.hasNext()) {
			DpkmPeers p = iter.next();
			if (p.cid == peers.cid) {
				peers.dpidA = p.dpidA;
				peers.dpidB = p.dpidB;
				exists = true;
				break;
			}
		}
		if (!exists) {
			status = "Error! No peer connection with this id exists.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		} else {
			// Send delete peer message to one switch, delete second after status response.
			configureWG.sendDeletePeerMessage(peers.dpidA, peers.dpidB, false);
			status = "DPKM_DELETE_PEER message sent to switch.";

			return ("{\"status\" : \"" + status + "\"}");
		}
    }
    
    /** 
	 * Converts peer information given in json format to a DpkmPeers object.
	 * Maps each json value to a field in DpkmPeers.
	 * @param fmJson Json structure containing peer information.  
	 * @return DpkmPeers switch peer object created from json. 
	 */
    public static DpkmPeers jsonToDpkmPeer(String fmJson) {
		DpkmPeers peers = new DpkmPeers();
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;
		try {
			try {
				jp = f.createParser(fmJson);
			} catch (JsonParseException e) {
				throw new IOException(e);
			}
			jp.nextToken();
			if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
				throw new IOException("Expected START_OBJECT");
			}
			while (jp.nextToken() != JsonToken.END_OBJECT) {
				if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
					throw new IOException("Expected FIELD_NAME");
				}
				
				String n = jp.getCurrentName();
				jp.nextToken();
				if (jp.getText().equals("")) {
					continue;
				}
				if (n.equalsIgnoreCase("cid")) {
					try {
						peers.cid = Integer.parseInt(jp.getText());
					} catch (NumberFormatException e) {
						log.error("Unable to parse connect id: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("switchIdSource")) {
					try {
						peers.dpidA = jp.getText();
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse source switch DPID: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("ipv4Source")) {
					try {
						peers.ipv4AddrA = jp.getText();
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse source switch IPv4 Address: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("switchIdTarget")) {
					try {
						peers.dpidB = jp.getText();
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse target switch DPID: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("ipv4Target")) {
					try {
						peers.ipv4AddrB = jp.getText();
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse target switch IPv4 Address: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("endType")) {
					try {
						peers.status = jp.getText();
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse end type: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
			}
		} catch (IOException e) {
			log.error("Unable to parse JSON string: {}", e);
		}
		return peers;
	}
}
