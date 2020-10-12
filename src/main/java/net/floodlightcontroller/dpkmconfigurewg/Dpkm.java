package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.projectfloodlight.openflow.protocol.OFDpkmAddPeer;
import org.projectfloodlight.openflow.protocol.OFDpkmDeletePeer;
import org.projectfloodlight.openflow.protocol.OFDpkmStatus;
import org.projectfloodlight.openflow.protocol.OFDpkmTestReply;
import org.projectfloodlight.openflow.protocol.OFDpkmTestRequest;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFQueueStatsEntry;
import org.projectfloodlight.openflow.protocol.OFQueueStatsReply;
import org.projectfloodlight.openflow.protocol.OFQueueStatsRequest;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetQueue;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;

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
    protected IOFSwitchService switchService;
    protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWGResource.class);
    
	/** 
	 * Writes a DPKM_ADD_PEER message to the given switch sw for any configured switches in db. </br>
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. </br>
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
	 * Builds and writes a DPKM_ADD_PEER message to switch sw with params.</br>
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. </br>
	 * Used internally by sendAddPeerMessage and constructAddPeerMessage. 
	 * @param sw Instance of a switch connected to the controller. 
	 * @param peerPubKey Public Key of the peer to be added.
	 * @param peerIPv4 IPv4 Address of the peer to be added.
	 * @param peerIPv4WG WireGuard Address of the peer to be added. 
	 */
	protected void sendAddPeerMessageInternal(IOFSwitch sw, String peerPubKey, String peerIPv4, String peerIPv4WG) {
		try {
			String sourceIPv4 = getIp(sw, false);
		    // If no connection exists add new record with status 'PID1ONLY'.
		    // Otherwise, update connection to status 'BOTH'. 
		    if(checkConnected(sourceIPv4, peerIPv4, 0) == 0) {
		    	addPeerConnection(sourceIPv4, peerIPv4);
		    } 
		    else if(checkConnected(sourceIPv4, peerIPv4, 7) > 0) {
		    	updatePeerInfo(sourceIPv4, peerIPv4, 4);
		    }
		    else {
		    	updatePeerInfo(sourceIPv4, peerIPv4, 5);
		    }
		    OFDpkmAddPeer addPeerMsg = sw.getOFFactory().buildDpkmAddPeer()
				    .setKey(peerPubKey)
				    .setIpv4Addr(peerIPv4)
				    .setIpv4Wg(peerIPv4WG)
				    .build();
		    sw.write(addPeerMsg);
		}
		catch(Exception e) {
			e.printStackTrace();
			System.out.println("Exception Thrown at sendAddPeerMessage.");
		}
	}
	
	/** 
	 * Builds and writes a DPKM_DELETE_PEER message to switch sw with params. </br>
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. </br>
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
		}
		catch(NullPointerException e) {
			System.out.println("NullPointerException Thrown at sendDeletePeerMessage.");
		}
	}
	
	/** 
	 * Returns the DatapathId of switch with address ipv4Addr or matching id from db or Error.
	 * @param ipv4Addr IPv4 Address of a switch.
	 * @param id Integer id of db record.
	 * @param isId Boolean to choose SQL statement (true=id). 
	 * @return String DatapathId of a switch or error.
	 */
	protected String getDpId(String ipv4Addr, int id, boolean isId) {
		String getDpidSQL = String.format("SELECT Dpid FROM ConfiguredPeers WHERE IPv4Addr = '%s';",ipv4Addr);
		if(isId) {
			getDpidSQL = String.format("SELECT Dpid FROM ConfiguredPeers WHERE id = '%s';",id);
		}
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
	 * Returns the Ipv4 Address or WireGuard address of switch sw from db or Error. 
	 * @param sw IOFSwitch instance of a switch.
	 * @param wg Boolean to choose SQL statement (true=WG).
	 * @return String Ipv4 address of a switch or error.
	 */
	protected String getIp(IOFSwitch sw, boolean wg) {
		String getSQL = String.format("SELECT IPv4Addr FROM ConfiguredPeers WHERE "
				+ "Dpid = '%s';",sw.getId().toString());
		if(wg) {
			getSQL = String.format("SELECT IPv4AddrWG FROM ConfiguredPeers WHERE "
					+ "Dpid = '%s';",sw.getId().toString());
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement getIp = connect.prepareStatement(getSQL);) {
			boolean isResult = getIp.execute();
	    	do {
	    		try (ResultSet rs = getIp.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getString(1));
	    			}
	    			isResult = getIp.getMoreResults();
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
	 * Returns the cryptoperiod of switch dpid from db or -1. 
	 * @param dpid DatapathId of the switch.
	 * @return Integer cryptoperiod or -1 if error.
	 */
	protected int getCryptoperiod(String dpid) {
		String getSQL = String.format("SELECT Cryptoperiod FROM ConfiguredPeers WHERE Dpid = '%s';",dpid);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement get = connect.prepareStatement(getSQL);) {
			boolean isResult = get.execute();
	    	do {
	    		try (ResultSet rs = get.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getInt(1));
	    			}
	    			isResult = get.getMoreResults();
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
		}
		return -1;
	}
	
	/** 
	 * Returns boolean compromised for the switch with dpid. 
	 * @param dpid DatapathId of the switch.
	 * @return boolean value in compromised field of switch or true by default 
	 * 		   to prevent actions against non-existent switch.
	 */
	public boolean checkCompromised(String dpid) {
		String checkComp = String.format("SELECT Compromised FROM ConfiguredPeers WHERE Dpid = '%s';", dpid);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement check = connect.prepareStatement(checkComp);) {
			boolean isResult = check.execute();
	    	do {
	    		try (ResultSet rs = check.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getBoolean(1));
	    			}
	    			isResult = check.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return true;
	}
	
	/** 
	 * Returns count of peer connections using SQL queries based on statusType or -1 if error. </br>
	 * Default: count of connections between ipv4AddrA and ipv4AddrB. </br>
	 * statusType(1): count of connections with the status 'KEY CHANGED'.</br>
	 * statusType(2): count of connections with the status 'REMOVED'.</br>
	 * statusType(3): count of connections with communicating TRUE.</br>
	 * statusType(4): count of connections with the status 'PID1ONLY'.</br>
	 * statusType(5): count of connections with the status 'BOTH'.</br>
	 * statusType(6): count of connections with the status 'BOTH CHANGED'.</br>
	 * statusType(7): count of connections with the status 'BOTH REMOVED'.</br>
	 * Used internally for a number of conditional statements.  
	 * @param ipv4AddrA IPv4 Address of a switch 'A'.
	 * @param ipv4AddrB IPv4 Address of a switch 'B'.
	 * @param statusType Integer used as a flag. 
	 * @return int Connection count or error (-1).
	 */
	public int checkConnected(String ipv4AddrA, String ipv4AddrB, int statusType) {
		// Check for connections between given addresses.
		String checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
				+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
				+ "Status != 'KEY CHANGED' AND Status != 'BOTH CHANGED';",
				ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		// Check connections where status is KEY CHANGED. 
		if(statusType == 1) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Status = 'KEY CHANGED';",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Check connections where status is REMOVED. 
		else if(statusType == 2) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Status = 'REMOVED';",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Check connections where status is COMMUNICATING.
		else if(statusType == 3) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Communicating = true;",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Checks connections where status is PID1ONLY.
		else if(statusType == 4) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Status = 'PID1ONLY';",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Checks connections where status is BOTH.
		else if(statusType == 5) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Status = 'BOTH';",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Checks connections where status is BOTH CHANGED.
		else if(statusType == 6) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Status = 'BOTH CHANGED';",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		// Checks connections where status is BOTH REMOVED.
		else if(statusType == 7) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Status = 'BOTH REMOVED';",
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
			DpkmConfigureWG.log.error("Failed to access the database when checking peer connections.");
			return -1;
		}
		return -1;
	}
	
	/** 
	 * Returns count of any connections with ipv4Addr as a peer.</br>
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
	 * in DPKM_STATUS message msg sent by switch sw. </br>
	 * Used internally to add a record for a new WireGuard configured switch.
	 * @param msg OFDpkmStatus response message received from the switch.
	 * @param sw Instance of a switch connected to the controller. 
	 */
	protected void writeSwitchToDB(OFDpkmStatus msg, IOFSwitch sw) {
		String sql = "INSERT INTO cntrldb.ConfiguredPeers VALUES (default, ?, ?, ?, ? , ?, ?, ?, ?, ?)";
		Timestamp currentTime = new Timestamp(Calendar.getInstance().getTime().getTime());
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
	        writeDB.setTimestamp(9, currentTime);
	        writeDB.executeUpdate();
	        connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Updates the database by modifying an existing record with the information contained 
	 * in DPKM_STATUS message msg sent by switch sw.</br>
	 * Used internally to update an existing record for a new WireGuard key.
	 * @param msg OFDpkmStatus response message received from the switch.
	 * @param sw Instance of a switch connected to the controller. 
	 */
	protected void updateSwitchInDB(OFDpkmStatus msg, IOFSwitch sw) {
		String updateSwitch = ("UPDATE cntrldb.ConfiguredPeers SET Cryptoperiod=?, "
				+ "PubKey2=PubKey1, PubKey1=?,Status=?,Compromised=?, IPv4AddrWG=?, "
				+ "Dpid=?, Since=? WHERE IPv4Addr=?");
		Timestamp currentTime = new Timestamp(Calendar.getInstance().getTime().getTime());
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(updateSwitch);) {
			writeDB.setString(8, msg.getIpv4Addr());
			writeDB.setInt(1, currentCryptoperiod);
			writeDB.setString(2, msg.getKey());
			writeDB.setString(3, "CONFIGURED");
			writeDB.setInt(4, 0);
			writeDB.setString(5, msg.getIpv4Wg());
			writeDB.setString(6, sw.getId().toString());
			writeDB.setTimestamp(7, currentTime);
			writeDB.executeUpdate();
			connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** 
	 * Updates the database by modifying an existing record with the matching id 
	 * to compromised = true. </br>
	 * Used internally to simulate compromise of a switch.
	 * @param id Integer id of record in database table.
	 */
	protected void updateSwitchCompromised(int id) {
		String updateSwitch = String.format("UPDATE cntrldb.ConfiguredPeers SET Status='COMPROMISED', Compromised=true "
    			+ "WHERE id = '%s'", id);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(updateSwitch);) {
			writeDB.executeUpdate(updateSwitch);
			connect.close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("Failed to compromise the switch.");
		}
	}
	
	/** 
	 * Updates the database by inserting a new record with the information contained 
	 * in DPKM_STATUS message msg.</br>
	 * Used internally to add a record for a new WireGuard peer connection.
	 * @param ipv4Addr IPv4 Address of the source peer switch.
	 * @param ipv4AddrPeer IPv4 Address of the target peer switch.
	 */
	protected void addPeerConnection(String ipv4Addr, String ipv4AddrPeer) {
		String addPeerQuery = String.format("INSERT INTO cntrldb.CommunicatingPeers(Cid,PID1,PID2,Status,Communicating) "
				+ "VALUES(default,(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),"
				+ "(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),'PID1ONLY',default);", 
				ipv4Addr,ipv4AddrPeer);
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
	 * in DPKM_STATUS message msg.</br>
	 * Chooses an SQL Query based on statusChange.</br>
	 * Default: set connection status as 'CONNECTED'.</br>
	 * statusChange(1): set connection status as 'KEY CHANGED'.</br>
	 * statusChange(2): set connection status as 'REMOVED'.</br>
	 * statusChange(3): set connection status as 'COMMUNICATING'.</br> 
	 * statusChange(4): set connection status as 'PID1ONLY'. </br>
	 * statusChange(5): set connection status as 'BOTH'.</br>
	 * statusChange(6): set connection status as 'BOTH CHANGED'.</br>
	 * statusChange(7): set connection status as 'BOTH REMOVED'.</br>
	 * Used internally to update an existing peer connection to reflect state of switch. 
	 * @param ipv4Addr IPv4 Address of the source peer switch.
	 * @param ipv4AddrPeer IPv4 Address of the target peer switch.
	 * @param statusChange Integer used as a flag. 
	 */
	protected void updatePeerInfo(String ipv4Addr, String ipv4AddrPeer, int statusChange) {
		// Default status is CONNECTED.
		String updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='CONNECTED'"
				+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
				ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		// Key linked to a peer interface has changed so connection status is KEY CHANGED. 
		if (statusChange == 1) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='KEY CHANGED'"
					+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		}
		// Key linked to a peer interface has been removed so connection status is REMOVED.
		else if (statusChange == 2) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='REMOVED'"
					+ " WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') OR "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4Addr);
		}
		// Communication started so connection status is COMMUNICATING.
		else if (statusChange == 3) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='COMMUNICATING',"
					+ "Communicating = true "
					+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		}
		// Maintain connection but only peer on one so connection status is PID1ONLY. 
		else if (statusChange == 4) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='PID1ONLY'"
					+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		}
		// Message sent to both but not confirmed so connection status is BOTH. 
		else if (statusChange == 5) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='BOTH'"
					+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		}
		// Both peer keys have changed so connection status is BOTH CHANGED. 
		else if (statusChange == 6) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='BOTH CHANGED'"
					+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		}
		
		// Both peer keys have been removed from the interfaces so connection status is BOTH REMOVED. 
		else if (statusChange == 7) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='BOTH REMOVED'"
					+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
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
	 * in DPKM_STATUS message msg. </br>
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
	 * Updates the database by removing the record matching the address ipv4Addr. </br>
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
