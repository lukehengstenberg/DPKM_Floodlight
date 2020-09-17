package net.floodlightcontroller.dpkmconfigurewg;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.types.SwitchMessagePair;
import net.floodlightcontroller.storage.IStorageSourceService;

import org.projectfloodlight.openflow.types.DatapathId;
import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class DpkmConfigureWGResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	protected IOFSwitchService switchService;
	
	@Get("json")
	public List<DpkmSwitch> retrieve() {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		return configureWG.getSwitches();
	}
	
	@Post
	public String configure(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = jsonToDpkmSwitch(fmJson);
		if (node == null) {
			return "{\"status\" : \"Error! Could not parse switch info, see log for details.\"}";
		}
		String status = null;
		configureWG.sendSetKeyMessage(DatapathId.of(node.dpid), node.cryptoperiod);
		status = "DPKM_SET_KEY message sent to switch.";
		// Need to use cryptoperiod here to begin a timer. 
		return ("{\"status\" : \"" + status + "\"}");
	}
	
	@Delete
	public String delete(String fmJson) {
		IDpkmConfigureWGService configureWG = 
				(IDpkmConfigureWGService)getContext().getAttributes()
				.get(IDpkmConfigureWGService.class.getCanonicalName());
		DpkmSwitch node = jsonToDpkmSwitch(fmJson);
		if (node == null) {
			return "{\"status\" : \"Error! Could not parse switch info, see log for details.\"}";
		}
		String status = null;
		boolean exists = false;
		Iterator<DpkmSwitch> iter = configureWG.getSwitches().iterator();
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
			}
		} catch (IOException e) {
			log.error("Unable to parse JSON string: {}", e);
		}
		return node;
	}
}
