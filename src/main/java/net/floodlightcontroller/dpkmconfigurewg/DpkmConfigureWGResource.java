package net.floodlightcontroller.dpkmconfigurewg;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import net.floodlightcontroller.core.internal.IOFSwitchService;
import org.projectfloodlight.openflow.types.DatapathId;
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
 * REST APIs for getting all configured switches, adding/configuring a new switch,
 * and deleting a configured switch. </br>
 * Takes json data from UI and deserializes, executing corresponding function.   
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmConfigureWGResource extends ServerResource {
	protected static Logger log = 
			LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	protected IOFSwitchService switchService;
	
	/** 
	 * Returns a full list of configured switches from the db in json format. 
	 * @return List<DpkmSwitch> List of WG switches from db.
	 * @see DpkmConfigureWG#getSwitches()
	 */
	@Get("json")
	public List<DpkmSwitch> retrieve() {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		return configureWG.getSwitches();
	}
	
	/** 
	 * Configures WG interface in the given switch and sets the cryptoperiod.</br>
	 * Deserializes to get dpid and cryptoperiod, sending SET_KEY message on success.
	 * @param fmJson Json structure containing switch information.  
	 * @return String status either success or error.
	 * @see #jsonToDpkmSwitch(String)
	 * @see DpkmConfigureWG#sendSetKeyMessage(DatapathId, int)
	 * @see DpkmError#checkError(String) 
	 */
	@Post
	public String configure(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = jsonToDpkmSwitch(fmJson);
		String status = null;
		if (node == null) {
			status = "Error! Could not parse switch info, see log for details.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		if(configureWG.checkError(node.dpid) > 0) {
			status = "Switch has an unresolved error that requires administrator "
					+ "attention. See log for details.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		configureWG.sendSetKeyMessage(DatapathId.of(node.dpid), node.cryptoperiod);
		status = "DPKM_SET_KEY message sent to switch.";
		return ("{\"status\" : \"" + status + "\"}");
	}
	
	/** 
	 * Deletes/unconfigures WG interface for switch matching the given id.</br>
	 * Deserializes to get id, finds db record, sending DELETE_KEY message on success.
	 * @param fmJson Json structure containing switch information.  
	 * @return String status either success or error. 
	 * @see #jsonToDpkmSwitch(String)
	 * @see DpkmConfigureWG#getSwitches()
	 * @see DpkmConfigureWG#sendDeleteKeyMessage(DatapathId)
	 */
	@Delete
	public String delete(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = jsonToDpkmSwitch(fmJson);
		String status = null;
		if (node == null) {
			status = "Error! Could not parse switch info, see log for details.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		}
		boolean exists = false;
		Iterator<DpkmSwitch> iter = configureWG.getSwitches().iterator();
		// Loop through switch records to find switch information.
		while (iter.hasNext()) {
			DpkmSwitch s = iter.next();
			if (s.id == node.id) {
				node.dpid = s.dpid;
				exists = true;
				break;
			}
		}
		if (!exists) {
			status = "Error! No switch with this id exists.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		} else {
			configureWG.sendDeleteKeyMessage(DatapathId.of(node.dpid));
			status = "DPKM_DELETE_KEY message sent to switch.";
			return ("{\"status\" : \"" + status + "\"}");
		}
	}
	
	/** 
	 * Converts switch information given in json format to a DpkmSwitch object.</br>
	 * Maps each json value to a field in DpkmSwitch.
	 * @param fmJson Json structure containing switch information.  
	 * @return DpkmSwitch switch object created from json.
	 * @exception IOException if parsing json fails.
	 * @see DpkmSwitch 
	 */
	public static DpkmSwitch jsonToDpkmSwitch(String fmJson) {
		DpkmSwitch node = new DpkmSwitch();
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
				if (n.equalsIgnoreCase("id")) {
					try {
						node.id = Integer.parseInt(jp.getText());
					} catch (NumberFormatException e) {
						log.error("Unable to parse switch id: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("switchid")) {
					try {
						node.dpid = jp.getText();
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse switch DPID: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("cryptoperiod")) {
					try {
						node.cryptoperiod = Integer.parseInt(jp.getText());
					} catch (NumberFormatException e) {
						log.error("Unable to parse cryptoperiod: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
				else if (n.equalsIgnoreCase("revType")) {
					try {
						node.status = jp.getText();
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse revType: {}", jp.getText());
						//TODO should return some error message via HTTP message
					}
				}
			}
		} catch (IOException e) {
			log.error("Unable to parse JSON string: {}", e);
		}
		return node;
	}
}
