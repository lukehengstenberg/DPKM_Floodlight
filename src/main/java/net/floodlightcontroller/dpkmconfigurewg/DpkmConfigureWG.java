
package net.floodlightcontroller.dpkmconfigurewg;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
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
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFRequest;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionDpkmSetKey;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionPopVlan;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxmDpkmMethod;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.ICMPv4Type;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U8;
import org.projectfloodlight.openflow.types.VlanVid;
import org.python.google.common.primitives.Longs;
import org.sdnplatform.sync.ISyncService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.util.concurrent.ListenableFuture;
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
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.util.ConcurrentCircularBuffer;

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
public class DpkmConfigureWG extends Dpkm implements IFloodlightModule, IDpkmConfigureWGService, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWG.class);
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected IRestApiService restApiService;
    int testcount = 0;
	
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
    
	/** 
	 * Processes the status message sent by the switch.
	 * Uses the content of the message to query the database and respond accordingly.
	 * @param sw Instance of a switch connected to the controller.
	 * @param msg The received OpenFlow DPKM Status message.
	 * @throws IOException.  
	 */
	private void processStatusMessage(IOFSwitch sw, OFDpkmStatus msg) throws IOException {
		log.info(String.format("A status response was received from switch %s.", sw.getId().toString()));
		// Executed if the status response shows WG has been configured.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_CONFIGURED) {
			log.info(String.format("Switch %s has been configured successfully.", sw.getId().toString()));
			// Adds the new WG switch to the database.
			if(checkIPExists(msg.getIpv4Addr()).equals("0")) {
				writeSwitchToDB(msg, sw);
				// Checks for and adds any configured switches as peers. 
				if(checkConfigured() >= 2) {
					constructAddPeerMessage(sw, msg.getIpv4Addr());
				}
				else if(checkConfigured() == 1) {
					log.info("No Peers to be added.");
				} else {
					log.error("An error was encountered when adding a peer.");
				}
			} 
			// Logs if controller fails to access the database. 
			else if(checkIPExists(msg.getIpv4Addr()).equals("Error")) {
				log.error("An error was encountered when adding switch info to DB.");
			} else {
				// Updates existing switch details for new configuration. 
				updateSwitchInDB(msg,sw);
				// Checks for and adds any configured and unconnected switches as peers.
				// TODO: This is broken.
				if(checkConfigured() >= 2 && checkConnectedAny(msg.getIpv4Addr()) == 0) {
					//constructAddPeerMessage(sw, msg.getIpv4Addr());
				}
				// Updates peer connection status to show that key changed.
				// Deletes the peer since key is now invalid. 
				else if(checkConnectedAny(msg.getIpv4Addr()) > 0) {
					Iterator<DpkmPeers> iter = getPeers().iterator();
					while (iter.hasNext()) {
						DpkmPeers p = iter.next();
						if (checkConnected(p.ipv4AddrA, p.ipv4AddrB, 1) > 0) {
							System.out.println(p.dpidA + " " + p.dpidB);
							// 5 == both keys changed.
							updatePeerInfo(p.ipv4AddrA, p.ipv4AddrB, 5);
							sendDeletePeerMessage(p.dpidA, p.dpidB, true);
						} else {
							System.out.println(p.dpidA + " " + p.dpidB);
							// 1 == key changed.
							updatePeerInfo(p.ipv4AddrA, p.ipv4AddrB, 1);
							sendDeletePeerMessage(p.dpidB, p.dpidA, true);
						}
					}
				}
				else if(checkConfigured() == 1) {
					log.info("No other WG configured switches in the DB. ");
				}
			}
		}
		// Executed if the status response shows a peer has been added.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_ADDED) {
			log.info(String.format("Switch %s has successfully added %s as a WG peer.", 
					sw.getId().toString(), getDpId(msg.getIpv4Peer())));
			// If connection is 'PID1ONLY' (4) only one switch has established connection.
			// Sends an add peer message to target peer, adding peer info to both WG interfaces.
			if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 4) > 0) {
				System.out.println("PID1ONLY");
				IOFSwitch targetSW = switchService.getSwitch(DatapathId.of(getDpId(msg.getIpv4Peer())));
				constructAddPeerMessage(targetSW, msg.getIpv4Peer());
			}
			// If connection is established on both, update peer connection status. 
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 5) > 0) {
				// 0 == key not changed. 
				System.out.println("BOTH");
				updatePeerInfo(msg.getIpv4Addr(), msg.getIpv4Peer(), 0);
			} 
			// If connection is 'CONNECTED' on both, confirm success.
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 0) > 0) {
				log.info(String.format("Full connection established between switch %s and switch %s.", 
						sw.getId().toString(), getDpId(msg.getIpv4Peer())));
			} else {
				log.error("An error was encountered when adding peer info to DB.");
			}
		}
		// Executed if the status response shows a peer has been deleted. 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_REMOVED) {
			log.info(String.format("Switch %s has successfully removed %s as a WG peer.", 
					sw.getId().toString(), getDpId(msg.getIpv4Peer())));
			// Remove connection if exists and status 'REMOVED' (key removed).
			if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 2) > 0) {
				removePeerConnection(msg);
				// Remove switch if no remaining peer connections.
				if(checkConnectedAny(msg.getIpv4Peer()) == 0) {
					removeSwitch(msg.getIpv4Peer());
				}
			}
			// Called if one of the keys in a connection has changed, so one peer is removed.
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 1) > 0) {
				// Update the connection to PID1ONLY since peer removed on one interface.
				updatePeerInfo(msg.getIpv4Addr(), msg.getIpv4Peer(), 6);
				// Re-add the peer but with new key.
				sendAddPeerMessage(sw.getId().toString(), getDpId(msg.getIpv4Peer()));
			}
			// Rare circumstance where both keys have changed. Connection removed and
			// recreated, status first PID1ONLY, then BOTH, then CONNECTED.
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 6) > 0) {
				removePeerConnection(msg);
				// Re-add one half of the peer connections with new key.
				constructAddPeerMessage(sw, msg.getIpv4Addr());
			}
			// Called if a new connection has been added (PID1ONLY) whilst awaiting second
			// DELETE_PEER message response. 
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 4) > 0) {
				// Re-add other half of the peer connections with new key.
				constructAddPeerMessage(sw, msg.getIpv4Addr());
			}
			// Sends delete peer message to target peer, deleting peer info on both WG interfaces. (if exists).
			// Removes connection from db. 
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 0) > 0) {
				IOFSwitch targetSW = switchService.getSwitch(DatapathId.of(getDpId(msg.getIpv4Peer())));
				constructDeletePeerMessage(targetSW, msg.getIpv4Peer(), false);
				removePeerConnection(msg);
			}
			// Connection removed from both switches. 
			else if(checkConnected(msg.getIpv4Addr(), msg.getIpv4Peer(), 0) == 0) {
				log.info("Peer removed from both switches.");
			}
		}
		// Executed if the status response shows a key has been revoked (unconfigured). 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_REVOKED) {
			log.info(String.format("Switch %s has successfully deleted it's key.", sw.getId().toString()));
			// If connections to unconfigured switch exist set connection status 'REMOVED'.
			// Send delete peer messages to all target peers.
			// Otherwise, remove switch from db. 
			if(checkConnectedAny(msg.getIpv4Addr()) >= 1) {
				// 2 == key removed.
				updatePeerInfo(msg.getIpv4Addr(), msg.getIpv4Peer(), 2);
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
		IOFSwitch sw = switchService.getSwitch(dpid);
		currentCryptoperiod = cryptoperiod;
		try {
			OFDpkmSetKey setKeyMsg = sw.getOFFactory().buildDpkmSetKey()
					.build();
			sw.write(setKeyMsg);
			log.info(String.format("DPKM_SET_KEY message sent to switch %s", dpid.toString()));
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
		IOFSwitch sw = switchService.getSwitch(dpid);
		try {
			OFDpkmDeleteKey delKeyMsg = sw.getOFFactory().buildDpkmDeleteKey()
					.build();
			sw.write(delKeyMsg);
			log.info(String.format("DPKM_DELETE_KEY message sent to switch %s", dpid.toString()));
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
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("Failed to access the database when retrieving switches.");
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
			log.error("Failed to access the database when retrieving peers.");
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
	    				sendAddPeerMessageInternal(sw, rs.getString(1),rs.getString(2),rs.getString(3));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("Failed to access the database when sending DPKM_ADD_PEER message.");
		} 
	}
	
	/** 
	 * Writes a DPKM_DELETE_PEER message to the switch with the given source dpid,
	 * removing the switch with the given target dpid as a peer.
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch removing the peer. 
	 * @param targetDpid DatapathId of the switch to be removed as a peer.
	 * @param keyChange Boolean specifying if the key has changed.  
	 */
	@Override
	public void sendDeletePeerMessage(String sourceDpid, String targetDpid, boolean keyChange) {
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
	    				sendDeletePeerMessageInternal(sw, rs.getString(1),rs.getString(2),rs.getString(3));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("Failed to access the database when sending DPKM_DELETE_PEER message.");
		} 
	}
	
	/** 
	 * Writes a FLOW_MOD message to both peer switches to push traffic through WG
	 * interface in port in accordance to the created flow table entry.
	 * This enables packets to be encrypted/decrypted and sent between the interfaces.   
	 * @param dpidA DatapathId of peer (switch) A. 
	 * @param dpidB DatapathId of peer (switch) B.  
	 */
    public void startCommunication(String dpidA, String dpidB) {
    	try {
    		// Initialise the switches. 
    		IOFSwitch peerA = switchService.getSwitch(DatapathId.of(dpidA));
			IOFSwitch peerB = switchService.getSwitch(DatapathId.of(dpidB));
			String ipv4A = getIp(peerA);
			String ipv4B = getIp(peerB);
    		// Create match conditions for switches.
			Match dpkmMatchA = peerA.getOFFactory().buildMatch()
					.setExact(MatchField.DPKM_METHOD, U8.of((short) 1))
					.setExact(MatchField.IN_PORT, OFPort.of(1))
					.setExact(MatchField.ETH_TYPE, EthType.IPv4)
					.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, TransportPort.of(51820))
					.setExact(MatchField.UDP_DST, TransportPort.of(51820))
					.setExact(MatchField.IPV4_SRC, IPv4Address.of(ipv4A))
					.setExact(MatchField.IPV4_DST, IPv4Address.of(ipv4B))
					.build();
			Match dpkmMatchB = peerB.getOFFactory().buildMatch()
					.setExact(MatchField.DPKM_METHOD, U8.of((short) 1))
					.setExact(MatchField.IN_PORT, OFPort.of(1))
					.setExact(MatchField.ETH_TYPE, EthType.IPv4)
					.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, TransportPort.of(51820))
					.setExact(MatchField.UDP_DST, TransportPort.of(51820))
					.setExact(MatchField.IPV4_SRC, IPv4Address.of(ipv4B))
					.setExact(MatchField.IPV4_DST, IPv4Address.of(ipv4A))
					.build();
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			// Set action as output aka output to port.
			OFActionOutput action = peerA.getOFFactory().actions().buildOutput()
					.setMaxLen(0xffFFffFF)
					.setPort(OFPort.of(1))
					.build();
			actionList.add(action);
			// Write instruction to apply action list to packet on switch end.
			OFInstructionApplyActions applyActions = peerA.getOFFactory().instructions().buildApplyActions()
					.setActions(actionList)
					.build();
			ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
			instructionList.add(applyActions);
			// Construct FLOW_ADD messages with matches and actions/instructions.
			OFFlowAdd flowA = peerA.getOFFactory().buildFlowAdd()
					.setBufferId(OFBufferId.NO_BUFFER)
					.setHardTimeout(0)
					.setIdleTimeout(0)
					.setPriority(32768)
					.setTableId(TableId.of(2))
					.setMatch(dpkmMatchA)
					.setInstructions(instructionList)
					.build();
			OFFlowAdd flowB = peerB.getOFFactory().buildFlowAdd()
					.setBufferId(OFBufferId.NO_BUFFER)
					.setHardTimeout(0)
					.setIdleTimeout(0)
					.setPriority(32768)
					.setTableId(TableId.of(3))
					.setMatch(dpkmMatchB)
					.setInstructions(instructionList)
					.build();
			// Write FLOW_MOD messages to switches.
			peerA.write(flowA);
			peerB.write(flowB);
			// Update DB status, 3 == start communication.
			updatePeerInfo(ipv4A, ipv4B, 3);
			log.info(String.format("Communication between switch %s and switch %s started.",dpidA,dpidB));
		}
		catch(Exception e) {
			e.printStackTrace();
			log.error("Failed to access the database when sending FLOW_MOD message.");
		}
    }
    
    public void rekey(String dpid, int cryptoperiod) {
    	try {
    		//TODO: Fix Queue packets, use meters instead.
    		//queuePackets(dpid);
    		sendSetKeyMessage(DatapathId.of(dpid), cryptoperiod);
    		//deQueuePackets(dpid);
    	} catch(Exception e) {
    		e.printStackTrace();
    		log.error("Failed to rekey the switch.");
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
}
