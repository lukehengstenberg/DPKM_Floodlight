package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;

import org.projectfloodlight.openflow.protocol.OFDpkmAddPeer;
import org.projectfloodlight.openflow.protocol.OFDpkmDeletePeer;
import org.projectfloodlight.openflow.protocol.OFDpkmStatus;
import org.projectfloodlight.openflow.protocol.OFDpkmTestReply;
import org.projectfloodlight.openflow.protocol.OFDpkmTestRequest;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U8;

import net.floodlightcontroller.core.IOFSwitch;

/** 
 * Core internal functionality of the Data Plane Key Management protocol. </br>
 * Main utility is querying underlying db and sending messages to switch 
 * without direct interaction from administrator. 
 * 
 * @author Luke Hengstenberg
 * @version 1.0
 */
public class Dpkm {
    protected int currentCryptoperiod = 0;
    protected DpkmConfigureWG confWG;
    
	/** 
	 * Writes a DPKM_ADD_PEER message to the given switch sw for any configured switches in db.
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * Used internally to automatically add configured switches as peers. 
	 * @param sw Instance of a switch connected to the controller. 
	 * @param ipv4Addr IPv4 Address of the switch.  
	 */
	protected void constructAddPeerMessage(IOFSwitch sw, String ipv4Addr) {
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
	protected void sendAddPeerMessageInternal(IOFSwitch sw, String peerPubKey, String peerIPv4, String peerIPv4WG) {
		try {
		    OFDpkmAddPeer addPeerMsg = sw.getOFFactory().buildDpkmAddPeer()
				    .setKey(peerPubKey)
				    .setIpv4Addr(peerIPv4)
				    .setIpv4Wg(peerIPv4WG)
				    .build();
		    sw.write(addPeerMsg);
		    DpkmConfigureWG.log.info(String.format("DPKM_ADD_PEER message sent to switch %s", sw.getId().toString()));
		}
		catch(Exception e) {
			System.out.println("Exception Thrown at sendAddPeerMessage.");
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
	protected void constructDeletePeerMessage(IOFSwitch sw, String ipv4addr, boolean newKey) {
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
	protected void sendDeletePeerMessageInternal(IOFSwitch sw, String peerPubKey, String peerIPv4, String peerIPv4WG) {
		try {
		    OFDpkmDeletePeer deletePeerMsg = sw.getOFFactory().buildDpkmDeletePeer()
		    		.setKey(peerPubKey)
		    		.setIpv4Addr(peerIPv4)
				    .setIpv4Wg(peerIPv4WG)
				    .build();
		    sw.write(deletePeerMsg);
		    DpkmConfigureWG.log.info(String.format("DPKM_DELETE_PEER message sent to switch %s", sw.getId().toString()));
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
	protected void constructDeletePeerBadKey(String ipv4Addr) {
		// Gets list of peers from db, iterates finding any 
		// connections that match ipv4Addr. 
		Iterator<DpkmPeers> iter = confWG.getPeers().iterator();
		while (iter.hasNext()) {
			DpkmPeers p = iter.next();
			if (p.ipv4AddrA.equalsIgnoreCase(ipv4Addr)) {
				confWG.sendDeletePeerMessage(p.dpidB, p.dpidA);
			}
			if (p.ipv4AddrB.equalsIgnoreCase(ipv4Addr)) {
				confWG.sendDeletePeerMessage(p.dpidA, p.dpidB);
			}
		}
	}
	
	protected void startCommunication(IOFSwitch peerA, IOFSwitch peerB) {
		try {
			//TODO: Get IPs from DB. 
			Match dpkmMatchA = peerA.getOFFactory().buildMatch()
					.setExact(MatchField.DPKM_METHOD, U8.of((short) 1))
					.setExact(MatchField.IN_PORT, OFPort.of(1))
					.setExact(MatchField.ETH_TYPE, EthType.IPv4)
					.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, TransportPort.of(51820))
					.setExact(MatchField.UDP_DST, TransportPort.of(51820))
					.setExact(MatchField.IPV4_SRC, IPv4Address.of("192.168.0.8"))
					.setExact(MatchField.IPV4_DST, IPv4Address.of("192.168.0.13"))
					.build();
			Match dpkmMatchB = peerB.getOFFactory().buildMatch()
					.setExact(MatchField.DPKM_METHOD, U8.of((short) 1))
					.setExact(MatchField.IN_PORT, OFPort.of(1))
					.setExact(MatchField.ETH_TYPE, EthType.IPv4)
					.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, TransportPort.of(51820))
					.setExact(MatchField.UDP_DST, TransportPort.of(51820))
					.setExact(MatchField.IPV4_SRC, IPv4Address.of("192.168.0.13"))
					.setExact(MatchField.IPV4_DST, IPv4Address.of("192.168.0.8"))
					.build();
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			
			//OFActionPopVlan popVlan = peerA.getOFFactory().actions().popVlan();
			//actionList.add(popVlan);
			OFActionOutput action = peerA.getOFFactory().actions().buildOutput()
					.setMaxLen(0xffFFffFF)
					.setPort(OFPort.of(1))
					.build();
			actionList.add(action);
			OFInstructionApplyActions applyActions = peerA.getOFFactory().instructions().buildApplyActions()
					.setActions(actionList)
					.build();
			ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
			instructionList.add(applyActions);
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
			peerA.write(flowA);
			peerB.write(flowB);
		}
		catch(Exception e) {
			
		}
	}
	
	protected void sendTestRequestMessage(IOFSwitch sw) {
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
	
	protected void sendTestReplyMessage(IOFSwitch sw, OFDpkmTestRequest testRequestMsg) {
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
	protected String getDpId(String ipv4Addr) {
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
	protected String checkIPExists(String ipv4Addr) {
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
	protected int checkConfigured() {
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
	 * Returns count of any connections with ipv4Addr as a peer.
	 * Used internally for a number of conditional statements.  
	 * @param ipv4Addr IPv4 Address of a switch.
	 * @return int Connection count or error (-1).
	 */
	protected int checkConnectedAny(String ipv4Addr) {
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
	protected void writeSwitchToDB(OFDpkmStatus msg, IOFSwitch sw) {
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
	protected void updateSwitchInDB(OFDpkmStatus msg, IOFSwitch sw) {
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
	protected void addPeerConnection(OFDpkmStatus msg) {
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
	protected void updatePeerInfo(OFDpkmStatus msg, int statusChange) {
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
	protected void removePeerConnection(OFDpkmStatus msg) {
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
	protected void removeSwitch(String ipv4Addr) {
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
}
