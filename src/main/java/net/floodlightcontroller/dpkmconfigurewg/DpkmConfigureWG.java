
package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFDpkmDeleteKey;
import org.projectfloodlight.openflow.protocol.OFDpkmHeader;
import org.projectfloodlight.openflow.protocol.OFDpkmSetKey;
import org.projectfloodlight.openflow.protocol.OFDpkmStatus;
import org.projectfloodlight.openflow.protocol.OFDpkmStatusFlag;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowModify;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.restserver.IRestApiService;

/** 
 * Facilitator and handler of Data Plane Key Management protocol communication
 * between the controller and switch.</br>
 * Provides functionality to REST APIs used by the administrator. </br>
 * Adjusts WireGuard configuration by sending particular DPKM messages based on 
 * the status response received from the switch and desired logic of administrator. 
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmConfigureWG extends DpkmFlows implements IFloodlightModule, IDpkmConfigureWGService, IOFMessageListener {
	protected static Logger log = 
			LoggerFactory.getLogger(DpkmConfigureWG.class);
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected IRestApiService restApiService;
	
	@Override
	public String getName() {
		return "DpkmConfigureWG";
	}
	
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// All DPKM messages should be run past the error handler first. 
		return (type.equals(OFType.EXPERIMENTER) && 
				(name.equalsIgnoreCase("DpkmErrorHandler")));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	/** 
	 * Implements a message listener for messages of type experimenter </br>
	 * Executes appropriate functions based on received message subtype.
	 * @param sw Instance of a switch connected to the controller.
	 * @param msg The received OpenFlow message.
	 * @param cntx Floodlight context for registering the listener.
	 * @see #processStatusMessage(IOFSwitch, OFDpkmStatus)
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx){
		switch(msg.getType()) {
		    case EXPERIMENTER:
		    	// Cast the message to a DPKM OpenFlow experimenter message.
		    	OFDpkmHeader inExperimenter = (OFDpkmHeader) msg;
		    	// Subtype 0 means a set key message has been sent.
		    	if(inExperimenter.getSubtype() == 0) {
		    		log.info(String.format("DPKM_SET_KEY message sent to switch %s", 
		    				sw.getId().toString()));
		    		break;
		    	}
		    	// Subtype 1 means a delete key message has been sent.
		    	if(inExperimenter.getSubtype() == 1) {
		    		log.info(String.format("DPKM_DELETE_KEY message sent to switch %s", 
		    				sw.getId().toString()));
		    		break;
		    	}
		    	// Subtype 2 means an add peer message has been sent.
		    	if(inExperimenter.getSubtype() == 2) {
		    		log.info(String.format("DPKM_ADD_PEER message sent to switch %s", 
		    				sw.getId().toString()));
		    		break;
		    	}
		    	// Subtype 3 means a delete peer message has been sent. 
		    	if(inExperimenter.getSubtype() == 3) {
		    		log.info(String.format("DPKM_DELETE_PEER message sent to switch %s", 
		    				sw.getId().toString()));
		    		break;
		    	}
		    	// Subtype 4 means a get status message has been sent. 
		    	if(inExperimenter.getSubtype() == 4) {
		    		log.info(String.format("DPKM_GET_STATUS message sent to switch %s", 
		    				sw.getId().toString()));
		    		break;
		    	}
		    	// Subtype 5 means a status message has been received and should be processed. 
		    	if(inExperimenter.getSubtype() == 5) {
		    		processStatusMessage(sw, (OFDpkmStatus)msg);
		    		break;
		    	}
		    	// Subtype 6 means an error message has been received.
		    	// DEPRECIATED: Error messages are type (1) not experimenter.  
		    	if(inExperimenter.getSubtype() == 6) {
		    		log.info(String.format("DPKM_ERROR message received from switch %s", 
		    				sw.getId().toString()));
		    		break;
		    	}
		    	// Subtypes 7 & 8 were used for test request/response messages. 
		    	if(inExperimenter.getSubtype() == 7 || inExperimenter.getSubtype() == 8) {
		    		log.info(String.format("DPKM_TEST message received from switch %s", 
		    				sw.getId().toString()));
		    		break;
		    	}
		    	else {
		    		log.info("Caught an experimenter message but did not recognise subtype.");
		    	}
			default:
				break;
		}
		return Command.CONTINUE;
	}
    
	/** 
	 * Processes the status message sent by the switch based on the status flag.</br>
	 * Calls one of several functions to process based on type of status response.
	 * @param sw Instance of a switch connected to the controller.
	 * @param msg The received OpenFlow DPKM Status message.
	 * @see #processConfigured(IOFSwitch, DpkmSwitch)
	 * @see #processPeerAdded(IOFSwitch, DpkmPeers)
	 * @see #processPeerRemoved(IOFSwitch, DpkmPeers)
	 * @see #processRevoked(IOFSwitch, DpkmSwitch)
	 */
	private void processStatusMessage(IOFSwitch sw, OFDpkmStatus msg) {
		// Executed if the status response shows WG has been configured.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_CONFIGURED) {
			DpkmSwitch node = statusToNode(sw, msg);
			processConfigured(sw, node);
		}
		// Executed if the status response shows a peer has been added.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_ADDED) {
			DpkmPeers peer = statusToPeer(sw, msg);
			processPeerAdded(sw, peer);
		}
		// Executed if the status response shows a peer has been deleted. 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_REMOVED) {
			DpkmPeers peer = statusToPeer(sw, msg);
			processPeerRemoved(sw, peer);
		}
		// Executed if the status response shows a key has been revoked (unconfigured). 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_REVOKED) {
			DpkmSwitch node = statusToNode(sw, msg);
			processRevoked(sw, node);
		} 
	}
	
	/** 
	 * Processes the SET_KEY status response sent by the switch.</br>
	 * Uses the content of the node object to query the database and respond 
	 * accordingly.
	 * @param sw Instance of a switch connected to the controller.
	 * @param node DpkmSwitch object storing the configured node info.
	 * @see #sendAddPeerMessage(String, String)
	 * @see #sendDeletePeerMessage(String, String, boolean)
	 * @see #getPeers()
	 * @see #writeSwitchToDB(DpkmSwitch)
	 * @see #updateSwitchInDB(DpkmSwitch)
	 * @see #checkConnected(String, String, String)
	 * @see #updatePeerInfo(String, String, String)
	 */
	private synchronized void processConfigured(IOFSwitch sw, DpkmSwitch node) {
		log.info(String.format("Switch %s has been configured successfully.", 
				node.dpid));
		String ipv4 = node.ipv4Addr;
		// Adds the new WG switch to the database.
		if(checkIPExists(ipv4).equals("0")) {
			writeSwitchToDB(node);
			
			// Checks for and adds any configured switches as peers. 
			if(checkConfigured() >= 2) {
				constructAddPeerMessage(sw, ipv4);
			}
			else if(checkConfigured() == 1) {
				log.info("No Peers to be added.");
			} else {
				log.error("An error was encountered when adding a peer.");
			}
		} 
		// Logs if controller fails to access the database. 
		else if(checkIPExists(ipv4).equals("Error")) {
			log.error("An error was encountered when adding switch info to DB.");
		} else {
			// Updates existing switch details for new configuration. 
			updateSwitchInDB(node);
			
			// Delete peers on one or both interfaces based on state.
			if(checkConnectedAny(ipv4) > 0) {
				Iterator<DpkmPeers> iter = getPeers().iterator();
				// Loop through peer connections.
				while (iter.hasNext()) {
					DpkmPeers p = iter.next();
					// If status is switch A key changed then
					if (checkConnected(ipv4, p.ipv4AddrB, "KEY CHANGED") > 0) {
						// update to 'PID1ONLY' (for later use),
						updatePeerInfo(ipv4, p.ipv4AddrB, "PID1ONLY");
						// remove switch A old key from switch B.
						sendDeletePeerMessage(p.dpidB, p.dpidA, true);
					}
					// If status is switch B key changed then
					else if (checkConnected(p.ipv4AddrA, ipv4, "KEY CHANGED") > 0) {
						// update to 'PID1ONLY' (for later use),
						updatePeerInfo(p.ipv4AddrA, ipv4, "PID1ONLY");
						// remove switch B old key from switch A.
						sendDeletePeerMessage(p.dpidA, p.dpidB, true);
					}
					// If status is both keys changed then
					else if (checkConnected(ipv4, p.ipv4AddrB, "BOTH CHANGED") > 0) {
						// update to 'BOTH REMOVED' (for later use),
						updatePeerInfo(ipv4, p.ipv4AddrB, "BOTH REMOVED");
						// remove old keys from both interfaces. 
						sendDeletePeerMessage(p.dpidA, p.dpidB, true);
						sendDeletePeerMessage(p.dpidB, p.dpidA, true);
					}
					// If key previously revoked but now reconfigured,
					else if (checkConnected(ipv4, p.ipv4AddrB, "REVOKED") > 0) {
						// update to 'BOTH REMOVED' (for later use),
						updatePeerInfo(ipv4, p.ipv4AddrB, "BOTH REMOVED");
						// rebuild peer connection with new key.
						sendAddPeerMessage(p.dpidA, p.dpidB);
					}
					else if (checkConnected(p.ipv4AddrA, ipv4, "REVOKED") > 0) {
						updatePeerInfo(p.ipv4AddrA, ipv4, "BOTH REMOVED");
						sendAddPeerMessage(p.dpidB, p.dpidA);
					}
				}
			}
			else if(checkConfigured() == 1) {
				log.info("No other WG configured switches in the DB. ");
			}
		}
	}
	
	/** 
	 * Processes the ADD_PEER status response sent by the switch.</br>
	 * Uses the content of the peers object to query the database and respond 
	 * accordingly.
	 * @param sw Instance of a switch connected to the controller.
	 * @param peer DpkmPeers object storing the add peer connection info.
	 * @see #sendAddPeerMessage(String, String)
	 * @see #checkConnected(String, String, String)
	 * @see #updatePeerInfo(String, String, String)
	 * @see #handleFlowRekeying(IOFSwitch, IOFSwitch, boolean)
	 */
	private synchronized void processPeerAdded(IOFSwitch sw, DpkmPeers peer) {
		log.info(String.format("Switch %s has successfully added %s as a WG peer.", 
				peer.dpidA, peer.dpidB));
		// If connection is 'PID1ONLY' only one switch has established connection.
		if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "PID1ONLY") > 0) {
			// Add peer info to both WG interfaces.
			sendAddPeerMessage(peer.dpidB, peer.dpidA);
		}
		// If connection is established on both, update peer connection status. 
		else if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "BOTH") > 0) {
			updatePeerInfo(peer.ipv4AddrA, peer.ipv4AddrB, "CONNECTED");
			log.info(String.format("Full connection established between switch %s "
					+ "and switch %s.", peer.dpidA, peer.dpidB));
			// If connection was communicating, update peer connection status.
			if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "COMMUNICATING") > 0) {
				updatePeerInfo(peer.ipv4AddrA, peer.ipv4AddrB, "COMMUNICATING");
				IOFSwitch swPeer = switchService.getSwitch(DatapathId.of(peer.dpidB));
				// Restore previous flow configuration to continue encryption.
				handleFlowRekeying(sw, swPeer, false);
			} 
		} 
		// If connection is 'CONNECTED' on both, confirm success.
		else if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "CONNECTED") > 0) {
			log.info(String.format("Full connection established between switch %s "
					+ "and switch %s.", peer.dpidA, peer.dpidB));
		} else {
			log.error("An error was encountered when adding peer info to DB.");
		}
	}
	
	/** 
	 * Processes the DELETE_PEER status response sent by the switch.</br>
	 * Uses the content of the peers object to query the database and respond 
	 * accordingly.
	 * @param sw Instance of a switch connected to the controller.
	 * @param peer DpkmPeers object storing the delete peer connection info.
	 * @see #sendAddPeerMessage(String, String)
	 * @see #sendDeletePeerMessage(String, String, boolean)
	 * @see #checkConnected(String, String, String)
	 * @see #updatePeerInfo(String, String, String)
	 * @see #removePeerConnection(String, String)
	 * @see #removeSwitch(String)
	 */
	private synchronized void processPeerRemoved(IOFSwitch sw, DpkmPeers peer) {
		log.info(String.format("Switch %s has successfully removed %s as a WG peer.", 
				peer.dpidA, peer.dpidB));
		// Remove connection if exists and status 'REMOVED' (key removed).
		if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "REMOVED") > 0) {
			removePeerConnection(peer.ipv4AddrA, peer.ipv4AddrB);
			// Remove switch if no remaining peer connections.
			if(checkConnectedAny(peer.ipv4AddrB) == 0) {
				removeSwitch(peer.ipv4AddrB);
			}
		}
		// New connection added while awaiting 2nd DELETE_PEER response. 
		else if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "PID1ONLY") > 0) {
			// Re-add other half of the peer connection with new key.
			sendAddPeerMessage(peer.dpidA, peer.dpidB);
		}
		// Connection removed from both interfaces but should be rebuilt.
		else if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "BOTH REMOVED") > 0) {
			sendAddPeerMessage(peer.dpidA, peer.dpidB);
		}
		// Enables rebuilding of connections terminated during revocation.
		else if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "ENDREVOKED") > 0) {
			sendDeletePeerMessage(peer.dpidB, peer.dpidA, false);
			// "REVOKED" flag identifies connections to rebuild (revType = reConf).
			updatePeerInfo(peer.ipv4AddrA, peer.ipv4AddrB, "REVOKED");
		}
		// Standard delete procedure, remove info from both WG interfaces and db.
		else if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "CONNECTED") > 0) {
			sendDeletePeerMessage(peer.dpidB, peer.dpidA, false);
			removePeerConnection(peer.ipv4AddrA, peer.ipv4AddrB);
		}
		// Connection has been removed from both switches. 
		else if(checkConnected(peer.ipv4AddrA, peer.ipv4AddrB, "CONNECTED") == 0) {
			log.info("Peer removed from both switches.");
		}
	}
	
	/** 
	 * Processes the DELETE_KEY status response sent by the switch.</br>
	 * Uses the content of the node object to query the database and respond 
	 * accordingly.
	 * @param sw Instance of a switch connected to the controller.
	 * @param node DpkmSwitch object storing the unconfigured node info.
	 * @see #sendDeletePeerMessage(String, String, boolean)
	 * @see #getPeers()
	 * @see #endCommunication(String, String, String)
	 * @see #checkConnected(String, String, String)
	 * @see #updatePeerInfo(String, String, String)
	 * @see #removeSwitch(String)
	 */
	private synchronized void processRevoked(IOFSwitch sw, DpkmSwitch node) {
		log.info(String.format("Switch %s has successfully deleted it's key.", 
				node.dpid));
		if(checkConnectedAny(node.ipv4Addr) >= 1) {
			// Set connection status to 'REMOVED' for all connections.
			updatePeerInfo(node.ipv4Addr, "", "REMOVED");
			Iterator<DpkmPeers> iter = getPeers().iterator();
			while (iter.hasNext()) {
				DpkmPeers p = iter.next();
				// End communication and delete all peers or remove switch.
				if (p.ipv4AddrA.equalsIgnoreCase(node.ipv4Addr)) {
					if (checkConnected(p.ipv4AddrB, p.ipv4AddrA, 
							"COMMUNICATING") > 0) {
						endCommunication(p.dpidB, p.dpidA, "endWG");
					} else {
						sendDeletePeerMessage(p.dpidB, p.dpidA, false);
					}	
				}
				if (p.ipv4AddrB.equalsIgnoreCase(node.ipv4Addr)) {
					if (checkConnected(p.ipv4AddrA, p.ipv4AddrB, 
							"COMMUNICATING") > 0) {
						endCommunication(p.dpidA, p.dpidB, "endWG");
					} else {
						sendDeletePeerMessage(p.dpidA, p.dpidB, false);
					}
				}
			}
		} else {
			removeSwitch(node.ipv4Addr);
		}
	}
	
	/** 
	 * Writes a DPKM_SET_KEY message to the switch with the given dpid,
	 * and sets the cryptoperiod.</br>
	 * This triggers the switch to generate the keys, configuring its
	 * WireGuard interface, returning a DPKM_STATUS or error response message. 
	 * @param dpid DatapathId of the switch. 
	 * @param cryptoperiod Valid cryptoperiod (seconds) before rekeying.
	 * @exception Exception if sending set key message fails.  
	 */
	@Override
	public void sendSetKeyMessage(DatapathId dpid, int cryptoperiod) {
		IOFSwitch sw = switchService.getSwitch(dpid);
		currentCryptoperiod = cryptoperiod;
		try {
			OFDpkmSetKey setKeyMsg = sw.getOFFactory().buildDpkmSetKey()
					.build();
			sw.write(setKeyMsg);
		} catch(Exception e) {
			log.error("Unable to send DPKM_SET_KEY message.");
		}
	}
	
	/** 
	 * Writes a DPKM_DELETE_KEY message to the switch with the given dpid. </br>
	 * This triggers the switch to delete its keys, unconfiguring WireGuard,
	 * returning a DPKM_STATUS or error response message.
	 * @param dpid DatapathId of the switch.
	 * @exception Exception if sending delete key message fails.  
	 */
	@Override
	public void sendDeleteKeyMessage(DatapathId dpid) {
		IOFSwitch sw = switchService.getSwitch(dpid);
		try {
			OFDpkmDeleteKey delKeyMsg = sw.getOFFactory().buildDpkmDeleteKey()
					.build();
			sw.write(delKeyMsg);
		} catch(Exception e) {
			log.error("Unable to send DPKM_DELETE_KEY message.");
		}
	}
	
	/** 
	 * Returns a full list of configured switches from the db, mapping fields
	 * to DpkmSwitch objects. 
	 * @return List<DpkmSwitch> List of WG switches in db.
	 * @exception SQLException if SQL query to db fails.
	 * @see DpkmSwitch 
	 */
	@Override
	public List<DpkmSwitch> getSwitches() {
		String getSQL = "SELECT * FROM cntrldb.ConfiguredPeers;";
		ArrayList<DpkmSwitch> confSwitches = new ArrayList<DpkmSwitch>();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		// Connects to the database and executes the SQL statement. 
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement get = connect.prepareStatement(getSQL);) {
			boolean isResult = get.execute();
			do {
				try (ResultSet rs = get.getResultSet()) {
	    			while (rs.next()) {
	    				DpkmSwitch cSwitch = new DpkmSwitch();
	    				cSwitch.id = rs.getInt("id");
	    				cSwitch.dpid = rs.getString("Dpid");
	    				cSwitch.ipv4Addr = rs.getString("IPv4Addr");
	    				cSwitch.ipv4AddrWG = rs.getString("IPv4AddrWG");
	    				cSwitch.cryptoperiod = rs.getInt("Cryptoperiod");
	    				cSwitch.status = rs.getString("Status");
	    				cSwitch.compromised = rs.getBoolean("Compromised");
	    				cSwitch.since = dateFormat.format(rs.getTimestamp("Since"));
	    				confSwitches.add(cSwitch);
	    			}
	    			isResult = get.getMoreResults();
	    		}
			} while (isResult);
			connect.close();
		} catch (SQLException e) {
			log.error("Failed to access the database when retrieving switches.");
		}
		return confSwitches;
	}
	
	/** 
	 * Returns a full list of peers from the db, mapping fields
	 * to DpkmPeers objects. 
	 * @return List<DpkmPeers> List of WG peers in db.
	 * @exception SQLException if SQL query to db fails.
	 * @see DpkmPeers 
	 */
	@Override
	public List<DpkmPeers> getPeers() {
		String getSQL = "SELECT CommunicatingPeers.Cid, ConfiguredPeer1.Dpid as "
				+ "'Dpid1', ConfiguredPeer1.IPv4Addr as 'IPv4Addr1', "
				+ "ConfiguredPeer1.IPv4AddrWG as 'IPv4AddrWG1', "
				+ "ConfiguredPeer2.Dpid as 'Dpid2', "
				+ "ConfiguredPeer2.IPv4Addr as 'IPv4Addr2', "
				+ "ConfiguredPeer2.IPv4AddrWG as 'IPv4AddrWG2', "
				+ "CommunicatingPeers.Status FROM CommunicatingPeers  "
				+ "LEFT JOIN (ConfiguredPeers as ConfiguredPeer1) ON "
				+ "(CommunicatingPeers.PID1 = ConfiguredPeer1.id) "
				+ "LEFT JOIN (ConfiguredPeers as ConfiguredPeer2) ON "
				+ "(CommunicatingPeers.PID2 = ConfiguredPeer2.id) "
				+ "ORDER BY CommunicatingPeers.Cid;";
		ArrayList<DpkmPeers> confPeers = new ArrayList<DpkmPeers>();
		// Connects to the database and executes the SQL statement. 
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement get = connect.prepareStatement(getSQL);) {
			boolean isResult = get.execute();
			do {
				try (ResultSet rs = get.getResultSet()) {
	    			while (rs.next()) {
	    				DpkmPeers cPeer = new DpkmPeers();
	    				cPeer.cid = rs.getInt("Cid");
	    				cPeer.dpidA = rs.getString("Dpid1");
	    			    cPeer.ipv4AddrA = rs.getString("IPv4Addr1");
	    			    cPeer.ipv4AddrWGA = rs.getString("IPv4AddrWG1");
	    			    cPeer.dpidB = rs.getString("Dpid2");
	    			    cPeer.ipv4AddrB = rs.getString("IPv4Addr2");
	    			    cPeer.ipv4AddrWGB = rs.getString("IPv4AddrWG2");
	    			    cPeer.status = rs.getString("Status");
	    				confPeers.add(cPeer);
	    			}
	    			isResult = get.getMoreResults();
	    		}
			} while (isResult);
			connect.close();
		} catch (SQLException e) {
			log.error("Failed to access the database when retrieving peers.");
		}
		return confPeers;
	}
	
	/** 
	 * Writes a DPKM_ADD_PEER message to the switch with the given source dpid,
	 * adding the switch with the given target dpid as a peer.</br>
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch adding the peer. 
	 * @param targetDpid DatapathId of the switch to be added as a peer.
	 * @exception SQLException if SQL query to db fails.
	 * @see #sendAddPeerMessageInternal(IOFSwitch, String, String, String)  
	 */
	@Override
	public void sendAddPeerMessage(String sourceDpid, String targetDpid) {
		IOFSwitch sw = switchService.getSwitch(DatapathId.of(sourceDpid));
		String getSQL = String.format("SELECT PubKey1, IPv4Addr, IPv4AddrWG "
				+ "FROM cntrldb.ConfiguredPeers WHERE Dpid = '%s';", targetDpid);
		// Connects to the database and executes the SQL statement. 
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement peerInfo = connect.prepareStatement(getSQL);) {
			boolean isResult = peerInfo.execute();
	    	do {
	    		try (ResultSet rs = peerInfo.getResultSet()) {
	    			while (rs.next()) {
	    				// Calls internal function to build and write message.
	    				sendAddPeerMessageInternal(sw, rs.getString(1),
	    						rs.getString(2),rs.getString(3));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			log.error("Failed to access the database when sending DPKM_ADD_PEER "
					+ "message.");
		} 
	}
	
	/** 
	 * Writes a DPKM_DELETE_PEER message to the switch with the given source dpid,
	 * removing the switch with the given target dpid as a peer.</br>
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch removing the peer. 
	 * @param targetDpid DatapathId of the switch to be removed as a peer.
	 * @param keyChange Boolean specifying if the key has changed. 
	 * @exception SQLException if SQL query to db fails.
	 * @see #sendDeletePeerMessageInternal(IOFSwitch, String, String, String) 
	 */
	@Override
	public void sendDeletePeerMessage(String sourceDpid, String targetDpid, 
			boolean keyChange) {
		IOFSwitch sw = switchService.getSwitch(DatapathId.of(sourceDpid));
		String getSQL = String.format("SELECT PubKey1, IPv4Addr, IPv4AddrWG "
				+ "FROM cntrldb.ConfiguredPeers WHERE Dpid = '%s';", targetDpid);
		if (keyChange) {
			getSQL = String.format("SELECT PubKey2, IPv4Addr, IPv4AddrWG "
					+ "FROM cntrldb.ConfiguredPeers WHERE Dpid = '%s';", targetDpid);
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement peerInfo = connect.prepareStatement(getSQL);) {
			boolean isResult = peerInfo.execute();
	    	do {
	    		try (ResultSet rs = peerInfo.getResultSet()) {
	    			while (rs.next()) {
	    				// Calls internal function to build and write message.
	    				sendDeletePeerMessageInternal(sw, rs.getString(1),
	    						rs.getString(2),rs.getString(3));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			log.error("Failed to access the database when sending DPKM_DELETE_PEER "
					+ "message.");
		} 
	}
	
	/** 
	 * Writes a FLOW_MOD message to both peer switches to push traffic through WG
	 * interface in port in accordance to the created flow table entry.</br>
	 * Enables packets to be encrypted/decrypted and sent between the interfaces.   
	 * @param dpidA DatapathId of peer (switch) A. 
	 * @param dpidB DatapathId of peer (switch) B.
	 * @exception Exception if sending flow mod message fails.
	 * @see #constructFlowAdd(IOFSwitch, IOFSwitch) 
	 * @see #updatePeerInfo(String, String, String) 
	 */
    public void startCommunication(String dpidA, String dpidB) {
    	try {
    		// Initialise the switches. 
    		IOFSwitch peerA = switchService.getSwitch(DatapathId.of(dpidA));
			IOFSwitch peerB = switchService.getSwitch(DatapathId.of(dpidB));
			String ipv4A = getIp(dpidA, false);
			String ipv4B = getIp(dpidB, false);
			OFFlowAdd flowA = constructFlowAdd(peerA, peerB);
			OFFlowAdd flowB = constructFlowAdd(peerB, peerA);
			// Write FLOW_MOD (ADD) messages to switches.
			peerA.write(flowA);
			peerB.write(flowB);
			// Update DB status, 3 == start communication.
			updatePeerInfo(ipv4A, ipv4B, "COMMUNICATING");
			log.info(String.format("Communication between switch %s and switch %s "
					+ "started.",dpidA,dpidB));
		}
		catch(Exception e) {
			log.error("Failed to access the database when sending FLOW_MOD message.");
		}
    }
    
    /** 
	 * Writes a FLOW_MOD message to both peer switches to terminate communication
	 * entirely or continue communication unencrypted (not through WG). </br>
	 * This is decided by the administrator using the top level UI to set endType.   
	 * @param dpidA DatapathId of peer (switch) A. 
	 * @param dpidB DatapathId of peer (switch) B.
	 * @param endType Type of termination (all communication or WG only). 
	 * @see #constructFlowModify(IOFSwitch, IOFSwitch)
	 * @see #constructFlowDrop(IOFSwitch, IOFSwitch)
	 * @see #updatePeerInfo(String, String, String) 
	 */
    @Override
    public void endCommunication(String dpidA, String dpidB, String endType) {
    	// Initialise the switches. 
		IOFSwitch peerA = switchService.getSwitch(DatapathId.of(dpidA));
		IOFSwitch peerB = switchService.getSwitch(DatapathId.of(dpidB));
		
		// Continue communication unencrypted else end all.
		if(endType.equalsIgnoreCase("endWG")) {
			OFFlowModify flowA = constructFlowModify(peerA, peerB);
			OFFlowModify flowB = constructFlowModify(peerB, peerA);
			// Write FLOW_MOD (MODIFY) messages to switches.
			peerA.write(flowA);
			peerB.write(flowB);
			log.info(String.format("Communication between switch %s and switch "
					+ "%s now unencrypted.",dpidA,dpidB));
		} else {
			OFFlowModify flowA = constructFlowDrop(peerA, peerB);
			OFFlowModify flowB = constructFlowDrop(peerB, peerA);
			// Write FLOW_MOD (DROP) messages to switches.
			peerA.write(flowA);
			peerB.write(flowB);
			log.info(String.format("Communication between switch %s and switch "
					+ "%s ended.",dpidA,dpidB));
			// Make note of peer connection for reconfiguration revType. 
			if(endType.equalsIgnoreCase("endRev")) {
				updatePeerInfo(getIp(dpidA,false),getIp(dpidB,false),"ENDREVOKED");
			}
		}
		// Delete peer connection one interface at a time.
		sendDeletePeerMessage(dpidA, dpidB, false);
    }
    
    /** 
	 * Rekey's the switch after expiry of the given cryptoperiod.</br>
	 * This consists of reconfiguring the switch using a DPKM_SET_KEY message.   
	 * @param dpid DatapathId of the switch. 
	 * @param cryptoperiod Life span of the key in seconds.
	 * @exception Exception if any messages sent during rekeying fail.
	 * @see #sendSetKeyMessage(DatapathId, int)
	 * @see #getPeers()
	 * @see #checkConnected(String, String, String)  
	 * @see #updatePeerInfo(String, String, String)
	 * @see #handleFlowRekeying(IOFSwitch, IOFSwitch, boolean)
	 */
    @Override
    public synchronized void rekey(String dpid, int cryptoperiod) {
    	try {
    		if(!getIp(dpid,false).equalsIgnoreCase("Error")) {
    			String ipv4 = getIp(dpid,false);
    			if(checkConnectedAny(ipv4) > 0) {
    				Iterator<DpkmPeers> iter = getPeers().iterator();
    				while (iter.hasNext()) {
    					DpkmPeers p = iter.next();
    					if (p.ipv4AddrA.equalsIgnoreCase(ipv4) || 
    							p.ipv4AddrB.equalsIgnoreCase(ipv4)) {
    						if (checkConnected(p.ipv4AddrA, p.ipv4AddrB, 
    								"KEY CHANGED") > 0) {
    							// Set status as both keys changed.
    							updatePeerInfo(p.ipv4AddrA, p.ipv4AddrB, 
    									"BOTH CHANGED");
    						} else {
    							// Set status as one key changed.
    							updatePeerInfo(p.ipv4AddrA, p.ipv4AddrB, 
    									"KEY CHANGED");
    							// Temporarily redirect flow via normal port.
    							if (checkConnected(p.ipv4AddrA, p.ipv4AddrB, 
    									"COMMUNICATING") > 0) {
    								IOFSwitch peerA = switchService
    										.getSwitch(DatapathId.of(p.dpidA));
    								IOFSwitch peerB = switchService
    										.getSwitch(DatapathId.of(p.dpidB));
        							handleFlowRekeying(peerA, peerB, true);
        						}
    						}
    						
    					}
    					
    				}
    			}
    		}
    		sendSetKeyMessage(DatapathId.of(dpid), cryptoperiod);
    	} catch(Exception e) {
    		log.error("Failed to rekey the switch.");
    	}
    }
    
    /** 
	 * Compromises switch with id to trigger the revocation procedure.</br>
	 * This updates the db record and ends all communication with the switch.  
	 * @param id Integer value of switch record in db.
	 * @see #endCommunication(String, String, String)
	 * @see #getPeers()   
	 */
    @Override
    public void compromiseNode(int id) {
    	updateSwitchCompromised(id);
    	IOFSwitch sw = switchService.getSwitch(DatapathId.of(getDpId(" ",id,true)));
    	String ipv4 = getIp(sw.getId().toString(),false);
    	if(checkConnectedAny(ipv4) > 0) {
    		Iterator<DpkmPeers> iter = getPeers().iterator();
			while (iter.hasNext()) {
				DpkmPeers p = iter.next();
				if (p.ipv4AddrA.equalsIgnoreCase(ipv4) || 
						p.ipv4AddrB.equalsIgnoreCase(ipv4)) {
					endCommunication(p.dpidA, p.dpidB, "endRev");
				}
			}
    	}
    }
	
    /** 
	 * Carries out the revocation procedure for a compromised switch dpid.</br>
	 * Based on the top-level policy this means reconfiguring the switch with 
	 * a SET_KEY message or terminating the switch with a DELETE_KEY message.
	 * @param dpid DatapathId of the switch.
	 * @param revType Revocation type either reconfigure or terminate switch.
	 * @see #sendSetKeyMessage(DatapathId, int) 
	 * @see #sendDeleteKeyMessage(DatapathId)
	 * @see #removeAllPeerConnections(String)  
	 */
    @Override
    public void revoke(String dpid, String revType) {
    	// Reconfigure the compromised node else terminate completely.
    	if(revType.equalsIgnoreCase("reConf")) {
    		int cryptoperiod = getCryptoperiod(dpid);
    		if(cryptoperiod != -1) {
    			sendSetKeyMessage(DatapathId.of(dpid), cryptoperiod);
    		}
    	} else {
    		removeAllPeerConnections(dpid);
    		sendDeleteKeyMessage(DatapathId.of(dpid));
    	}
    }
    
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = 
				new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IDpkmConfigureWGService.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = 
				new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IDpkmConfigureWGService.class, this);
	    return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = 
				new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IRestApiService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		this.floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        this.switchService = context.getServiceImpl(IOFSwitchService.class);
        this.restApiService = context.getServiceImpl(IRestApiService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.EXPERIMENTER, this);
        restApiService.addRestletRoutable(new DpkmConfigureWGWebRoutable());
	}
}
