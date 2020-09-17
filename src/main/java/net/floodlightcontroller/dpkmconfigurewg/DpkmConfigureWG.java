
package net.floodlightcontroller.dpkmconfigurewg;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.projectfloodlight.openflow.protocol.OFDpkmAddPeer;
import org.projectfloodlight.openflow.protocol.OFDpkmDeleteKey;
import org.projectfloodlight.openflow.protocol.OFDpkmDeletePeer;
import org.projectfloodlight.openflow.protocol.OFDpkmHeader;
import org.projectfloodlight.openflow.protocol.OFDpkmKeyFlag;
import org.projectfloodlight.openflow.protocol.OFDpkmKeyTlv;
import org.projectfloodlight.openflow.protocol.OFDpkmSetKey;
import org.projectfloodlight.openflow.protocol.OFDpkmStatus;
import org.projectfloodlight.openflow.protocol.OFDpkmStatusFlag;
import org.projectfloodlight.openflow.protocol.OFDpkmStatusTlv;
import org.projectfloodlight.openflow.protocol.OFDpkmTestReply;
import org.projectfloodlight.openflow.protocol.OFDpkmTestRequest;
import org.projectfloodlight.openflow.protocol.OFEchoRequest;
import org.projectfloodlight.openflow.protocol.OFExperimenter;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionDpkmSetKey;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.python.google.common.primitives.Longs;
import org.sdnplatform.sync.ISyncService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.mysql.cj.jdbc.MysqlDataSource;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.SwitchMessagePair;
import net.floodlightcontroller.dhcpserver.DHCPServer;
import net.floodlightcontroller.firewall.FirewallRule;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.util.ConcurrentCircularBuffer;

/** 
 * 
 * @author Luke Hengstenberg
 */
public class DpkmConfigureWG implements IFloodlightModule, IDpkmConfigureWGService, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWG.class);
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected IRestApiService restApiService;
    int testcount = 0;
    private int currentCryptoperiod = 0;
	
	@Override
	public String getName() {
		return "DpkmConfigureWG";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	/** 
	 * Implements a message listener for messages of type experimenter.
	 * Executes appropriate functions based on received message subtype.
	 * @param sw Instance of a switch connected to the controller.
	 * @param msg The received OpenFlow message.
	 * @param cntx Floodlight context for registering the listener. 
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx){
		switch(msg.getType()) {
		    case EXPERIMENTER:
		    	// Cast the message to a DPKM OpenFlow experimenter message.
		    	OFDpkmHeader inExperimenter = (OFDpkmHeader) msg;
		    	// Subtype 5 means a status message has been received and should be processed. 
		    	if(inExperimenter.getSubtype() == 5) {
		    		try {
						processStatusMessage(sw, (OFDpkmStatus)msg);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
		    		break;
		    	}
		    	if(inExperimenter.getSubtype() == 8) {
		    		sendTestRequestMessage(sw);
		    		break;
		    	}
		    	else {
		    		System.out.println(inExperimenter.getSubtype());
		    		System.out.println("Caught an experimenter message but did not recognise subtype.");
		    	}
			default:
				break;
		}
		return Command.CONTINUE;
	}
    
	private void processTestRequest(IOFSwitch sw, OFDpkmTestRequest msg) throws IOException {
		sendTestReplyMessage(sw,msg);
	}
	
	/** 
	 * Processes the status message sent by the switch.
	 * Uses the content of the message to query the database and respond accordingly.
	 * @param sw Instance of a switch connected to the controller.
	 * @param msg The received OpenFlow DPKM Status message.
	 * @throws IOException.  
	 */
	private void processStatusMessage(IOFSwitch sw, OFDpkmStatus msg) throws IOException {
		System.out.println("Status msg received.");
		// Executed if the status response shows WG has been configured.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_CONFIGURED) {
			// Adds the new WG switch to the database.
			if(checkIPExists(msg.getIpv4Addr()).equals("0")) {
				writeSwitchToDB(msg, sw);
				// Checks for and adds any configured switches as peers. 
				if(checkConfigured() >= 2) {
					constructAddPeerMessage(sw, msg.getIpv4Addr());
				}
				else if(checkConfigured() == 1) {
					System.out.println("No Peers to be added. ");
				} else {
					System.out.println("Error adding peer.");
				}
			} 
			// Logs if controller fails to access the database. 
			else if(checkIPExists(msg.getIpv4Addr()).equals("Error")) {
				System.out.println("Error adding switch to DB.");
			} else {
				// Updates existing switch details for new configuration. 
				updateSwitchInDB(msg,sw);
				// Checks for and adds any configured and unconnected switches as peers.
				if(checkConfigured() >= 2 && checkConnectedAny(msg.getIpv4Addr()) == 0) {
					constructAddPeerMessage(sw, msg.getIpv4Addr());
				}
				// Updates peer connection status to show that key changed.
				// Deletes the peer since key is now invalid. 
				else if(checkConnectedAny(msg.getIpv4Addr()) >= 1) {
					// 1 == key changed.
					updatePeerInfo(msg, 1);
					constructDeletePeerMessage(sw, msg.getIpv4Addr(), false);
				}
				else if(checkConfigured() == 1) {
					System.out.println("No other nodes in the DB.");
				}
			}
		}
		// Executed if the status response shows a peer has been added.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_ADDED) {
			// Adds a new peer connection to the database (if no existing).
			// Sends an add peer message to target peer, adding peer info to both WG interfaces.
			if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 0) == 0) {
				addPeerConnection(msg);
				IOFSwitch targetSW = switchService.getSwitch(DatapathId.of(getDpId(msg.getIpv4Peer())));
				constructAddPeerMessage(targetSW, msg.getIpv4Peer());
			}
			// If connection is established on both, update peer connection status. 
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 0) >= 1) {
				// 0 == key not changed. 
				updatePeerInfo(msg, 0);
				// TODO: Start communication
			} else {
				System.out.println("An error occurred adding peer info to DB.");
			}
		}
		// Executed if the status response shows a peer has been deleted. 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_REMOVED) {
			// Remove connection if exists and status 'REMOVED' (key removed).
			if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 2) > 0) {
				removePeerConnection(msg);
				// Remove switch if no remaining peer connections.
				if(checkConnectedAny(msg.getIpv4Peer()) == 0) {
					removeSwitch(msg.getIpv4Peer());
				}
			}
			// Sends delete peer message to target peer, deleting peer info on both WG interfaces. (if exists).
			// Removes connection from db. 
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 0) > 0) {
				IOFSwitch targetSW = switchService.getSwitch(DatapathId.of(getDpId(msg.getIpv4Peer())));
				constructDeletePeerMessage(targetSW, msg.getIpv4Peer(), false);
				removePeerConnection(msg);
			}
			// Sends delete peer message to target peer but with old public key. (if exists & key changed). 
			// Removes connection from db.
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 1) > 0) {
				IOFSwitch targetSW = switchService.getSwitch(DatapathId.of(getDpId(msg.getIpv4Peer())));
				constructDeletePeerMessage(targetSW, msg.getIpv4Peer(), true);
				removePeerConnection(msg);
			}
			// Connection removed from both switches. 
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 0) == 0) {
				System.out.println("Peer removed from both switches.");
			}
		}
		// Executed if the status response shows a key has been revoked (unconfigured). 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_REVOKED) {
			System.out.println("Response received");
			// If connections to unconfigured switch exist set connection status 'REMOVED'.
			// Send delete peer messages to all target peers.
			// Otherwise, remove switch from db. 
			if(checkConnectedAny(msg.getIpv4Addr()) >= 1) {
				// 2 == key removed.
				updatePeerInfo(msg, 2);
			    constructDeletePeerBadKey(msg.getIpv4Addr());
			} else {
				removeSwitch(msg.getIpv4Addr());
			}
		} 
	}
	
	/** 
	 * Writes a DPKM_SET_KEY message to the switch with the given dpid,
	 * and sets the cryptoperiod.
	 * This triggers the switch to generate the keys, configuring its
	 * WireGuard interface, returning a DPKM_STATUS or error response message. 
	 * @param dpid DatapathId of the switch. 
	 * @param cryptoperiod Valid cryptoperiod (seconds) before rekeying.  
	 */
	@Override
	public void sendSetKeyMessage(DatapathId dpid, int cryptoperiod) {
		System.out.println("Sendsetkeymessage has been called.");
		IOFSwitch sw = switchService.getSwitch(dpid);
		currentCryptoperiod = cryptoperiod;
		try {
			OFDpkmSetKey setKeyMsg = sw.getOFFactory().buildDpkmSetKey()
					.build();
			
			sw.write(setKeyMsg);
		} catch(Exception e) {
			System.out.println("NullPointerException Thrown!");
			log.error("Unable to send DPKM_SET_KEY message.");
		}
	}
	
	/** 
	 * Writes a DPKM_DELETE_KEY message to the switch with the given dpid.
	 * This triggers the switch to delete its keys, unconfiguring WireGuard,
	 * returning a DPKM_STATUS or error response message.
	 * @param dpid DatapathId of the switch.  
	 */
	@Override
	public void sendDeleteKeyMessage(DatapathId dpid) {
		System.out.println("sendDeleteKeyMessage has been called.");
		IOFSwitch sw = switchService.getSwitch(dpid);
		try {
			OFDpkmDeleteKey delKeyMsg = sw.getOFFactory().buildDpkmDeleteKey()
					.build();
			sw.write(delKeyMsg);
		} catch(Exception e) {
			System.out.println("NullPointerException Thrown!");
			log.error("Unable to send DPKM_DELETE_KEY message.");
		}
	}
	
	/** 
	 * Returns a full list of configured switches from the db, mapping fields
	 * to DpkmSwitch objects. 
	 * @return List<DpkmSwitch> List of WG switches in db. 
	 */
	@Override
	public List<DpkmSwitch> getSwitches() {
		String getSQL = "SELECT * FROM cntrldb.ConfiguredPeers;";
		ArrayList<DpkmSwitch> confSwitches = new ArrayList<DpkmSwitch>();
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
	    				confSwitches.add(cSwitch);
	    			}
	    			isResult = get.getMoreResults();
	    		}
			} while (isResult);
			connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return confSwitches;
	}
	
	/** 
	 * Returns a full list of peers from the db, mapping fields
	 * to DpkmPeers objects. 
	 * @return List<DpkmPeers> List of WG peers in db. 
	 */
	@Override
	public List<DpkmPeers> getPeers() {
		String getSQL = "SELECT CommunicatingPeers.Cid, ConfiguredPeer1.Dpid as 'Dpid1', ConfiguredPeer1.IPv4Addr as 'IPv4Addr1', "
				+ "ConfiguredPeer1.IPv4AddrWG as 'IPv4AddrWG1', ConfiguredPeer2.Dpid as 'Dpid2', "
				+ "ConfiguredPeer2.IPv4Addr as 'IPv4Addr2', ConfiguredPeer2.IPv4AddrWG as 'IPv4AddrWG2', "
				+ "CommunicatingPeers.Status FROM CommunicatingPeers  "
				+ "LEFT JOIN (ConfiguredPeers as ConfiguredPeer1) ON (CommunicatingPeers.PID1 = ConfiguredPeer1.id) "
				+ "LEFT JOIN (ConfiguredPeers as ConfiguredPeer2) ON (CommunicatingPeers.PID2 = ConfiguredPeer2.id) "
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return confPeers;
	}
	
	/** 
	 * Writes a DPKM_ADD_PEER message to the switch with the given source dpid,
	 * adding the switch with the given target dpid as a peer.
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch adding the peer. 
	 * @param targetDpid DatapathId of the switch to be added as a peer.  
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
	    				sendAddPeerMessageInternal(sw, rs.getString("PubKey1"),rs.getString("IPv4Addr"),rs.getString("IPv4AddrWG"));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	
	/** 
	 * Writes a DPKM_ADD_PEER message to the given switch sw for any configured switches in db.
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * Used internally to automatically add configured switches as peers. 
	 * @param sw Instance of a switch connected to the controller. 
	 * @param ipv4Addr IPv4 Address of the switch.  
	 */
	private void constructAddPeerMessage(IOFSwitch sw, String ipv4Addr) {
		String getCred = String.format("SELECT PubKey1, IPv4Addr, IPv4AddrWG "
				+ "FROM cntrldb.ConfiguredPeers WHERE Status='CONFIGURED' AND IPv4Addr != '%s';", ipv4Addr);
		// Connects to the database and executes the SQL statement. 
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement peerInfo = connect.prepareStatement(getCred);) {
			boolean isResult = peerInfo.execute();
	    	do {
	    		try (ResultSet rs = peerInfo.getResultSet()) {
	    			while (rs.next()) {
	    				// Calls internal function to build and write message.
	    				sendAddPeerMessageInternal(sw, rs.getString("PubKey1"),rs.getString("IPv4Addr"),rs.getString("IPv4AddrWG"));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Builds and writes a DPKM_ADD_PEER message to switch sw with params.
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * Used internally by sendAddPeerMessage and constructAddPeerMessage. 
	 * @param sw Instance of a switch connected to the controller. 
	 * @param peerPubKey Public Key of the peer to be added.
	 * @param peerIPv4 IPv4 Address of the peer to be added.
	 * @param peerIPv4WG WireGuard Address of the peer to be added. 
	 */
	private void sendAddPeerMessageInternal(IOFSwitch sw, String peerPubKey, String peerIPv4, String peerIPv4WG) {
		System.out.println("SendAddPeerMessage has been called.");
		try {
		    OFDpkmAddPeer addPeerMsg = sw.getOFFactory().buildDpkmAddPeer()
				    .setKey(peerPubKey)
				    .setIpv4Addr(peerIPv4)
				    .setIpv4Wg(peerIPv4WG)
				    .build();
		    sw.write(addPeerMsg);
		}
		catch(Exception e) {
			System.out.println("Exception Thrown at sendAddPeerMessage.");
		}
	}
	
	/** 
	 * Writes a DPKM_DELETE_PEER message to the switch with the given source dpid,
	 * removing the switch with the given target dpid as a peer.
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch removing the peer. 
	 * @param targetDpid DatapathId of the switch to be removed as a peer.  
	 */
	@Override
	public void sendDeletePeerMessage(String sourceDpid, String targetDpid) {
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
	    				sendDeletePeerMessageInternal(sw, rs.getString("PubKey1"),rs.getString("IPv4Addr"),rs.getString("IPv4AddrWG"));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	
	/** 
	 * Writes a DPKM_DELETE_PEER message to the given switch sw for any peer switches in db.
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * Used internally to automatically remove peers. 
	 * @param sw Instance of a switch connected to the controller. 
	 * @param ipv4Addr IPv4 Address of the switch.
	 * @param newKey Boolean to use alternative SQL query targeting old PubKey.
	 * 				 Necessary for circumstances where key changes.  
	 */
	private void constructDeletePeerMessage(IOFSwitch sw, String ipv4addr, boolean newKey) {
		String getCred = String.format("SELECT A.PubKey1, A.IPv4Addr, A.IPv4AddrWG FROM "
				+ "ConfiguredPeers A INNER JOIN CommunicatingPeers B ON "
				+ "(A.id = B.PID1 OR A.id = B.PID2) AND A.IPv4Addr != '%s' "
				+ "WHERE B.PID1 IN (SELECT id FROM ConfiguredPeers WHERE IPv4Addr = '%s') OR "
				+ "B.PID2 IN (SELECT id FROM ConfiguredPeers WHERE IPv4Addr ='%s');",
				ipv4addr,ipv4addr,ipv4addr);
		if(newKey) {
			getCred = String.format("SELECT A.PubKey2, A.IPv4Addr, A.IPv4AddrWG FROM "
					+ "ConfiguredPeers A INNER JOIN CommunicatingPeers B ON "
					+ "(A.id = B.PID1 OR A.id = B.PID2) AND A.IPv4Addr != '%s' "
					+ "WHERE B.PID1 IN (SELECT id FROM ConfiguredPeers WHERE IPv4Addr = '%s') OR "
					+ "B.PID2 IN (SELECT id FROM ConfiguredPeers WHERE IPv4Addr ='%s');",
					ipv4addr,ipv4addr,ipv4addr);
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement peerInfo = connect.prepareStatement(getCred);) {
			boolean isResult = peerInfo.execute();
	    	do {
	    		try (ResultSet rs = peerInfo.getResultSet()) {
	    			while (rs.next()) {
	    				// Calls internal function to build and write message.
	    				sendDeletePeerMessageInternal(sw, rs.getString(1),rs.getString(2),rs.getString(3));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Builds and writes a DPKM_DELETE_PEER message to switch sw with params.
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * Used internally by sendDeletePeerMessage and constructDeletePeerMessage. 
	 * @param sw Instance of a switch connected to the controller. 
	 * @param peerPubKey Public Key of the peer to be removed.
	 * @param peerIPv4 IPv4 Address of the peer to be removed.
	 * @param peerIPv4WG WireGuard Address of the peer to be removed. 
	 */
	private void sendDeletePeerMessageInternal(IOFSwitch sw, String peerPubKey, String peerIPv4, String peerIPv4WG) {
		System.out.println("SendDeletePeerMessage has been called.");
		try {
		    OFDpkmDeletePeer deletePeerMsg = sw.getOFFactory().buildDpkmDeletePeer()
		    		.setKey(peerPubKey)
		    		.setIpv4Addr(peerIPv4)
				    .setIpv4Wg(peerIPv4WG)
				    .build();
		    sw.write(deletePeerMsg);
		}
		catch(NullPointerException e) {
			System.out.println("NullPointerException Thrown at sendDeletePeerMessage.");
		}
	}
	
	/** 
	 * Writes a DPKM_DELETE_PEER message to all with the switch with
	 * IPv4 Address ipv4Addr in their peer table. 
	 * This triggers the switches to remove the peer info from their WireGuard interfaces, 
	 * returning DPKM_STATUS or error response messages. 
	 * Used internally after a key has been removed, ensuring no peer connections remain. 
	 * @param ipv4Addr IPv4 Address of the peer to be removed. 
	 */
	private void constructDeletePeerBadKey(String ipv4Addr) {
		// Gets list of peers from db, iterates finding any 
		// connections that match ipv4Addr. 
		Iterator<DpkmPeers> iter = getPeers().iterator();
		while (iter.hasNext()) {
			DpkmPeers p = iter.next();
			if (p.ipv4AddrA.equalsIgnoreCase(ipv4Addr)) {
				sendDeletePeerMessage(p.dpidB, p.dpidA);
			}
			if (p.ipv4AddrB.equalsIgnoreCase(ipv4Addr)) {
				sendDeletePeerMessage(p.dpidA, p.dpidB);
			}
		}
	}
	
	private void sendTestRequestMessage(IOFSwitch sw) {
		System.out.println("Sendtestrequestmessage has been called.");
		try {
		    OFDpkmTestRequest testRequestMsg = sw.getOFFactory().buildDpkmTestRequest()
		    		.build();
			
			sw.write(testRequestMsg);
		}
		catch(NullPointerException e) {
			System.out.println("NullPointerException Thrown!");
		}
	}
	
	private void sendTestReplyMessage(IOFSwitch sw, OFDpkmTestRequest testRequestMsg) {
		System.out.println("Sendtestreplymessage has been called.");
		try {
		    OFDpkmTestReply testReplyMsg = sw.getOFFactory().buildDpkmTestReply()
		    		.setXid(testRequestMsg.getXid())
		            .setData(testRequestMsg.getData())
		    		.build();
			
			sw.write(testReplyMsg);
		}
		catch(NullPointerException e) {
			System.out.println("NullPointerException Thrown!");
		}
	}
	
	/** 
	 * Returns the DatapathId of switch with address ipv4Addr from db or Error. 
	 * @param ipv4Addr IPv4 Address of a switch.
	 * @return String DatapathId of a switch or error.
	 */
	private String getDpId(String ipv4Addr) {
		String getDpidSQL = String.format("SELECT Dpid FROM ConfiguredPeers WHERE Status = 'CONFIGURED' AND IPv4Addr = '%s';",ipv4Addr);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement getDpid = connect.prepareStatement(getDpidSQL);) {
			boolean isResult = getDpid.execute();
	    	do {
	    		try (ResultSet rs = getDpid.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getString(1));
	    			}
	    			isResult = getDpid.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return("Error");
		}
    	return("Error");
	}
	
	/** 
	 * Returns count of records with matching ipv4Addr in db. 
	 * @param ipv4Addr IPv4 Address of a switch.
	 * @return String Count with address or error.
	 */
	private String checkIPExists(String ipv4Addr) {
		String checkIP = String.format("SELECT COUNT(*) FROM ConfiguredPeers WHERE IPv4Addr = '%s';",ipv4Addr);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement check = connect.prepareStatement(checkIP);) {
			boolean isResult = check.execute();
	    	do {
	    		try (ResultSet rs = check.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getString(1));
	    			}
	    			isResult = check.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return("Error");
		}
    	return("Error");
	}
	
	/**  
	 * @return int Number of switches with status 'CONFIGURED' in db or -1 if error.
	 */
	private int checkConfigured() {
		String checkConf = ("SELECT COUNT(*) FROM ConfiguredPeers WHERE STATUS = 'CONFIGURED';");
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement checkStatus = connect.prepareStatement(checkConf);) {
			boolean isResult = checkStatus.execute();
	    	do {
	    		try (ResultSet rs = checkStatus.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = checkStatus.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return -1;
		}
		return -1;
	}
	
	/** 
	 * Returns count of peer connections using SQL queries based on statusType or -1 if error.
	 * Default: count of connections between ipv4AddrA and ipv4AddrB.
	 * statusType(1): count of connections with the status 'KEY CHANGED'.
	 * statusType(2): count of connections with the status 'REMOVED'.
	 * Used internally for a number of conditional statements.  
	 * @param ipv4AddrA IPv4 Address of a switch 'A'.
	 * @param ipv4AddrB IPv4 Address of a switch 'B'.
	 * @param statusType Integer used as a flag. 
	 * @return int Connection count or error (-1).
	 */
	@Override
	public int checkConnected(String ipv4AddrA, String ipv4AddrB, int statusType) {
		// Check for connections between given addresses.
		String checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
				+ "WHERE Status !='KEY CHANGED' AND "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));",
				ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		// Check connections where status is KEY CHANGED. 
		if(statusType == 1) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE Status ='KEY CHANGED' AND "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Check connections where status is REMOVED. 
		else if(statusType == 2) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE Status ='REMOVED' AND "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement checkConn = connect.prepareStatement(checkQ);) {
			boolean isResult = checkConn.execute();
			do {
	    		try (ResultSet rs = checkConn.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = checkConn.getMoreResults();
	    		}
	    	} while (isResult);
			connect.close();
		} catch (Exception e) {
			System.out.println("Nullpointer thrown in checkConnected.");
			return -1;
		}
		return -1;
	}
	
	/** 
	 * Returns count of any connections with ipv4Addr as a peer.
	 * Used internally for a number of conditional statements.  
	 * @param ipv4Addr IPv4 Address of a switch.
	 * @return int Connection count or error (-1).
	 */
	private int checkConnectedAny(String ipv4Addr) {
		String checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
				+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));",
				ipv4Addr,ipv4Addr);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement checkConn = connect.prepareStatement(checkQ);) {
			boolean isResult = checkConn.execute();
	    	do {
	    		try (ResultSet rs = checkConn.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = checkConn.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return -1;
		}
		return -1;
	}
	
	/** 
	 * Updates the database by inserting a new record with the information contained 
	 * in DPKM_STATUS message msg sent by switch sw. 
	 * Used internally to add a record for a new WireGuard configured switch.
	 * @param msg OFDpkmStatus response message received from the switch.
	 * @param sw Instance of a switch connected to the controller. 
	 */
	private void writeSwitchToDB(OFDpkmStatus msg, IOFSwitch sw) {
		String sql = "INSERT INTO cntrldb.ConfiguredPeers VALUES (default, ?, ?, ?, ? , ?, ?, ?, ?)";
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(sql);) {
			// "Cryptoperiod, PubKey1, PubKey2, Status, Compromised, IPv4Addr, IPv4AddrWG, Dpid from cntrldb.ConfiguredPeers");
	        // Parameters start with 1
			writeDB.setInt(1, currentCryptoperiod);
	        writeDB.setString(2, msg.getKey());
	        writeDB.setString(3, " ");
	        writeDB.setString(4, "CONFIGURED");
	        writeDB.setInt(5, 0);
	        writeDB.setString(6, msg.getIpv4Addr());
	        writeDB.setString(7, msg.getIpv4Wg());
	        writeDB.setString(8, sw.getId().toString());
	        writeDB.executeUpdate();
	        connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Updates the database by modifying an existing record with the information contained 
	 * in DPKM_STATUS message msg sent by switch sw. 
	 * Used internally to update an existing record for a new WireGuard key.
	 * @param msg OFDpkmStatus response message received from the switch.
	 * @param sw Instance of a switch connected to the controller. 
	 */
	private void updateSwitchInDB(OFDpkmStatus msg, IOFSwitch sw) {
		String updateSwitch = ("UPDATE cntrldb.ConfiguredPeers SET Cryptoperiod=?, "
				+ "PubKey2=PubKey1, PubKey1=?,Status=?,Compromised=?, IPv4AddrWG=?, Dpid=? WHERE IPv4Addr=?");
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(updateSwitch);) {
			writeDB.setString(7, msg.getIpv4Addr());
			writeDB.setInt(1, currentCryptoperiod);
			writeDB.setString(2, msg.getKey());
			writeDB.setString(3, "CONFIGURED");
			writeDB.setInt(4, 0);
			writeDB.setString(5, msg.getIpv4Wg());
			writeDB.setString(6, sw.getId().toString());
			writeDB.executeUpdate();
			connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Updates the database by inserting a new record with the information contained 
	 * in DPKM_STATUS message msg. 
	 * Used internally to add a record for a new WireGuard peer connection.
	 * @param msg OFDpkmStatus response message received from the switch.
	 */
	private void addPeerConnection(OFDpkmStatus msg) {
		String addPeerQuery = String.format("INSERT INTO cntrldb.CommunicatingPeers(Cid,PID1,PID2,Status) "
				+ "VALUES(default,(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),"
				+ "(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),'PID1ONLY');", 
				msg.getIpv4Addr(),msg.getIpv4Peer());
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement addPeer = connect.prepareStatement(addPeerQuery);) {
			addPeer.executeUpdate(addPeerQuery);
			connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Updates the database by modifying an existing record with the information contained 
	 * in DPKM_STATUS message msg.
	 * Chooses an SQL Query based on statusChange.
	 * Default: set connection status as 'CONNECTED'.
	 * statusChange(1): set connection status as 'KEY CHANGED'.
	 * statusChange(2): set connection status as 'REMOVED'.  
	 * Used internally to update an existing peer connection to reflect state of switch. 
	 * @param msg OFDpkmStatus response message received from the switch.
	 * @param statusChange Integer used as a flag. 
	 */
	private void updatePeerInfo(OFDpkmStatus msg, int statusChange) {
		// Default status is CONNECTED.
		String updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='CONNECTED'"
				+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
				msg.getIpv4Addr(), msg.getIpv4Peer(), msg.getIpv4Peer(), msg.getIpv4Addr());
		// Key linked to a peer interface has changed so connection status is KEY CHANGED. 
		if (statusChange == 1) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='KEY CHANGED'"
					+ " WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') OR "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					msg.getIpv4Addr(), msg.getIpv4Addr());
		}
		// Key linked to a peer interface has been removed so connection status is REMOVED.
		else if (statusChange == 2) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='REMOVED'"
					+ " WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') OR "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					msg.getIpv4Addr(), msg.getIpv4Addr());
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement updateCon = connect.prepareStatement(updateQuery);) {
			updateCon.executeUpdate(updateQuery);
			connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Updates the database by removing the record matching the IP addresses contained 
	 * in DPKM_STATUS message msg. 
	 * Used internally to remove an existing peer connection.
	 * @param msg OFDpkmStatus response message received from the switch.
	 */
	private void removePeerConnection(OFDpkmStatus msg) {
		String removeQuery = String.format("DELETE FROM cntrldb.CommunicatingPeers WHERE "
				+ "PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
				msg.getIpv4Addr(), msg.getIpv4Peer(), msg.getIpv4Peer(), msg.getIpv4Addr());
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement removeCon = connect.prepareStatement(removeQuery);) {
			removeCon.executeUpdate(removeQuery);
			connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Updates the database by removing the record matching the address ipv4Addr. 
	 * Used internally to remove a WireGuard configured switch.
	 * @param ipv4Addr IPv4 Address of a switch.
	 */
	private void removeSwitch(String ipv4Addr) {
		String removeQuery = String.format("DELETE FROM cntrldb.ConfiguredPeers WHERE "
				+ "IPv4Addr='%s';", ipv4Addr);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement removeCon = connect.prepareStatement(removeQuery);) {
			removeCon.executeUpdate(removeQuery);
			connect.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IDpkmConfigureWGService.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IDpkmConfigureWGService.class, this);
	    return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
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
		//floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.EXPERIMENTER, this);
        restApiService.addRestletRoutable(new DpkmConfigureWGWebRoutable());
	}
	
    // Closes DB connection. 
//	private void close() {
//        try {
//            if (resultSet != null) {
//                resultSet.close();
//            }
//
//            if (statement != null) {
//                statement.close();
//            }
//
//            if (connect != null) {
//                connect.close();
//            }
//        } catch (Exception e) {
//            System.out.println("Failed to close Database connection.");
//        }
//    }
}
