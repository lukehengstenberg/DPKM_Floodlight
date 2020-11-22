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
import com.mysql.cj.exceptions.DataReadException;

import junit.framework.Assert;
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
	 * Writes a DPKM_ADD_PEER message to the given switch sw for any configured 
	 * switches in db. </br>
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. </br>
	 * Used internally to automatically add configured switches as peers. 
	 * @param sw Instance of a switch connected to the controller. 
	 * @param ipv4Addr IPv4 Address of the switch.  
	 */
	protected void constructAddPeerMessage(IOFSwitch sw, String ipv4Addr) {
		String getCred = String.format("SELECT PubKey1, IPv4Addr, IPv4AddrWG "
				+ "FROM cntrldb.ConfiguredPeers WHERE Status='CONFIGURED' AND "
				+ "IPv4Addr != '%s';", ipv4Addr);
		// Connects to the database and executes the SQL statement. 
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(getCred);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				// Calls internal function to build and write message.
	    				sendAddPeerMessageInternal(sw, rs.getString("PubKey1"),
	    						rs.getString("IPv4Addr"),rs.getString("IPv4AddrWG"));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
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
	protected void sendAddPeerMessageInternal(IOFSwitch sw, String peerPubKey, 
			String peerIPv4, String peerIPv4WG) {
		try {
			String sourceIPv4 = getIp(sw.getId().toString(), false);
		    // If no connection exists add new record with status 'PID1ONLY'.
		    // Otherwise, update connection to status 'BOTH'. 
		    if(checkConnected(sourceIPv4, peerIPv4, "CONNECTED") == 0) {
		    	addPeerConnection(sourceIPv4, peerIPv4);
		    } 
		    else if(checkConnected(sourceIPv4, peerIPv4, "BOTH REMOVED") > 0) {
		    	updatePeerInfo(sourceIPv4, peerIPv4, "PID1ONLY");
		    }
		    else {
		    	updatePeerInfo(sourceIPv4, peerIPv4, "BOTH");
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
	protected void sendDeletePeerMessageInternal(IOFSwitch sw, String peerPubKey, 
			String peerIPv4, String peerIPv4WG) {
		try {
		    OFDpkmDeletePeer deletePeerMsg = sw.getOFFactory().buildDpkmDeletePeer()
		    		.setKey(peerPubKey)
		    		.setIpv4Addr(peerIPv4)
				    .setIpv4Wg(peerIPv4WG)
				    .build();
		    sw.write(deletePeerMsg);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	/** 
	 * Returns the DatapathId of switch with address ipv4Addr or matching id 
	 * from db or Error.
	 * @param ipv4Addr IPv4 Address of a switch.
	 * @param id Integer id of db record.
	 * @param isId Boolean to choose SQL statement (true=id). 
	 * @return String DatapathId of a switch or error.
	 */
	protected String getDpId(String ipv4Addr, int id, boolean isId) {
		String getDpidSQL = String.format("SELECT Dpid FROM ConfiguredPeers WHERE "
				+ "IPv4Addr = '%s';",ipv4Addr);
		if(isId) {
			getDpidSQL = String.format("SELECT Dpid FROM ConfiguredPeers WHERE "
					+ "id = '%s';",id);
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(getDpidSQL);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getString(1));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
    	return("Error");
	}
	
	/** 
	 * Returns the Ipv4 Address or WireGuard address of switch sw from db or Error. 
	 * @param dpid DatapathId of a switch.
	 * @param wg Boolean to choose SQL statement (true=WG).
	 * @return String Ipv4 address of a switch or error.
	 */
	protected String getIp(String dpid, boolean wg) {
		String getSQL = String.format("SELECT IPv4Addr FROM ConfiguredPeers WHERE "
				+ "Dpid = '%s';",dpid);
		if(wg) {
			getSQL = String.format("SELECT IPv4AddrWG FROM ConfiguredPeers WHERE "
					+ "Dpid = '%s';",dpid);
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(getSQL);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getString(1));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
    	return("Error");
	}
	
	/** 
	 * Returns the cryptoperiod of switch dpid from db or -1. 
	 * @param dpid DatapathId of the switch.
	 * @return Integer cryptoperiod or -1 if error.
	 */
	protected int getCryptoperiod(String dpid) {
		String getSQL = String.format("SELECT Cryptoperiod FROM ConfiguredPeers "
				+ "WHERE Dpid = '%s';",dpid);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(getSQL);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getInt(1));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
    	return -1;
	}
	
	/** 
	 * Returns count of records with matching ipv4Addr in db. 
	 * @param ipv4Addr IPv4 Address of a switch.
	 * @return String Count with address or error.
	 */
	protected String checkIPExists(String ipv4Addr) {
		String checkIP = String.format("SELECT COUNT(*) FROM ConfiguredPeers "
				+ "WHERE IPv4Addr = '%s';",ipv4Addr);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(checkIP);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getString(1));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
    	return("Error");
	}
	
	/**  
	 * @return int Number of switches with status 'CONFIGURED' in db or -1 if error.
	 */
	protected int checkConfigured() {
		String checkConf = ("SELECT COUNT(*) FROM ConfiguredPeers WHERE "
				+ "STATUS = 'CONFIGURED';");
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(checkConf);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
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
		String checkComp = String.format("SELECT Compromised FROM ConfiguredPeers "
				+ "WHERE Dpid = '%s';", dpid);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(checkComp);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getBoolean(1));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
		return true;
	}
	
	/** 
	 * Returns count of peer connections using SQL queries based on statusType 
	 * or -1 if error. </br>
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
	 * @param statusType String used as a flag. 
	 * @return int Connection count or error (-1).
	 */
	public int checkConnected(String ipv4AddrA, String ipv4AddrB, String statusType) {
		// Check for connections between given addresses.
		String checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
				+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
				+ "Status != 'KEY CHANGED' AND Status != 'BOTH CHANGED';",
				ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		if(statusType.equalsIgnoreCase("COMMUNICATING")) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Communicating = true;",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA);
		}
		else if(!statusType.equalsIgnoreCase("CONNECTED")) {
			checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
					+ "WHERE ((PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'))) AND "
					+ "Status = '%s';",
					ipv4AddrA,ipv4AddrB,ipv4AddrB,ipv4AddrA,statusType);
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(checkQ);) {
			boolean isResult = prep.execute();
			do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
			connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			DpkmConfigureWG.log.error("Failed to access the database when "
					+ "checking peer connections.");
			throw new IllegalArgumentException(e);
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
				PreparedStatement prep = connect.prepareStatement(checkQ);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		} 
		return -1;
	}
	
	/** 
	 * Returns unresolved error count for switch with DatapathId dpid.</br>
	 * Used internally for a number of conditional statements.  
	 * @param dpid DatapathId of a switch in string format.
	 * @return int Error count or -1.
	 */
	public int checkError(String dpid) {
		String checkQ = String.format("SELECT COUNT(*) FROM cntrldb.ErrorLog "
				+ "WHERE Dpid = '%s' AND Resolved = false;",
				dpid);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(checkQ);) {
			boolean isResult = prep.execute();
	    	do {
	    		try (ResultSet rs = prep.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = prep.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
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
	protected void writeSwitchToDB(DpkmSwitch node) {
		String sql = "INSERT INTO cntrldb.ConfiguredPeers VALUES "
				+ "(default, ?, ?, ?, ? , ?, ?, ?, ?, ?)";
		Timestamp currentTime = new Timestamp(Calendar.getInstance().getTime().getTime());
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(sql);) {
			prep.setInt(1, node.getCryptoperiod());
			prep.setString(2, node.getPubKey1());
			prep.setString(3, node.getPubKey2());
			prep.setString(4, node.getStatus());
			prep.setBoolean(5, node.getCompromised());
			prep.setString(6, node.getIpv4Addr());
			prep.setString(7, node.getIpv4AddrWG());
			prep.setString(8, node.getDpId());
			prep.setTimestamp(9, currentTime);
			prep.executeUpdate();
	        connect.close();
		} catch (NullPointerException | SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
	}
	
	/** 
	 * Updates the database by modifying an existing record with the information 
	 * contained in DPKM_STATUS message msg sent by switch sw.</br>
	 * Used internally to update an existing record for a new WireGuard key.
	 * @param msg OFDpkmStatus response message received from the switch.
	 * @param sw Instance of a switch connected to the controller. 
	 */
	protected void updateSwitchInDB(DpkmSwitch node) {
		String updateSwitch = ("UPDATE cntrldb.ConfiguredPeers SET Cryptoperiod=?, "
				+ "PubKey2=PubKey1, PubKey1=?,Status=?,Compromised=?, IPv4AddrWG=?, "
				+ "Dpid=?, Since=? WHERE IPv4Addr=?");
		Timestamp currentTime = new Timestamp(Calendar.getInstance().getTime().getTime());
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(updateSwitch);) {
			prep.setString(8, node.getIpv4Addr());
			prep.setInt(1, node.getCryptoperiod());
			prep.setString(2, node.getPubKey1());
			prep.setString(3, node.getStatus());
			prep.setBoolean(4, node.getCompromised());
			prep.setString(5, node.getIpv4AddrWG());
			prep.setString(6, node.getDpId());
			prep.setTimestamp(7, currentTime);
			prep.executeUpdate();
			connect.close();
		} catch (NullPointerException | SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
	}
	
	/** 
	 * Updates the database by modifying an existing record with the matching id 
	 * to compromised = true. </br>
	 * Used internally to simulate compromise of a switch.
	 * @param id Integer id of record in database table.
	 */
	protected void updateSwitchCompromised(int id) {
		String updateSwitch = String.format("UPDATE cntrldb.ConfiguredPeers SET "
				+ "Status='COMPROMISED', Compromised=true WHERE id = '%s'", id);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(updateSwitch);) {
			prep.executeUpdate(updateSwitch);
			connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			log.error("Failed to compromise the switch.");
			throw new IllegalArgumentException(e);
		}
	}
	
	/** 
	 * Updates the database by inserting a new peer connection between ipv4Addr
	 * and ipv4AddrPeer.</br>
	 * Used internally to add a record for a new WireGuard peer connection.
	 * @param ipv4Addr IPv4 Address of the source peer switch.
	 * @param ipv4AddrPeer IPv4 Address of the target peer switch.
	 */
	protected void addPeerConnection(String ipv4Addr, String ipv4AddrPeer) {
		String addPeerQuery = String.format("INSERT INTO cntrldb.CommunicatingPeers"
				+ "(Cid,PID1,PID2,Status,Communicating) VALUES(default,"
				+ "(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),"
				+ "(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),"
				+ "'PID1ONLY',default);", 
				ipv4Addr,ipv4AddrPeer);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(addPeerQuery);) {
			prep.executeUpdate(addPeerQuery);
			connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
	}
	
	/** 
	 * Updates the database by modifying an existing connection with matching IP 
	 * addresses ipv4Addr and ipv4AddrPeer.</br>
	 * Chooses an SQL Query based on integer statusChange.</br>
	 * Default: set connection status as 'CONNECTED'.</br>
	 * statusChange(1): set connection status as 'KEY CHANGED'.</br>
	 * statusChange(2): set connection status as 'REMOVED'.</br>
	 * statusChange(3): set connection status as 'COMMUNICATING'.</br> 
	 * statusChange(4): set connection status as 'PID1ONLY'. </br>
	 * statusChange(5): set connection status as 'BOTH'.</br>
	 * statusChange(6): set connection status as 'BOTH CHANGED'.</br>
	 * statusChange(7): set connection status as 'BOTH REMOVED'.</br>
	 * Used internally to update an existing peer connection to reflect state 
	 * of switch. 
	 * @param ipv4Addr IPv4 Address of the source peer switch.
	 * @param ipv4AddrPeer IPv4 Address of the target peer switch.
	 * @param statusChange String used as a flag. 
	 */
	protected void updatePeerInfo(String ipv4Addr, String ipv4AddrPeer, String statusChange) {
		// Set connection status to statusChange.
		String updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='%s'"
				+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
				statusChange, ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		// Key linked to a peer interface has been removed so connection status is REMOVED.
		if (statusChange.equalsIgnoreCase("REMOVED")) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='REMOVED'"
					+ " WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') OR "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4Addr);
		}
		// Communication started so connection status is COMMUNICATING.
		else if (statusChange.equalsIgnoreCase("COMMUNICATING")) {
			updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='COMMUNICATING',"
					+ "Communicating = true "
					+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
					+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
					+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
					ipv4Addr, ipv4AddrPeer, ipv4AddrPeer, ipv4Addr);
		}
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(updateQuery);) {
			prep.executeUpdate(updateQuery);
			connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
	}
	
	/** 
	 * Updates the database by removing the record matching the IP addresses  
	 * ipv4Addr and ipv4Peer. </br>
	 * Used internally to remove an existing peer connection.
	 * @param ipv4Addr IPv4 address of the current switch.
	 * @param ipv4Peer IPv4 address of the peer linked to the current switch.
	 */
	protected void removePeerConnection(String ipv4Addr, String ipv4Peer) {
		String removeQuery = String.format("DELETE FROM cntrldb.CommunicatingPeers WHERE "
				+ "PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
				ipv4Addr, ipv4Peer, ipv4Peer, ipv4Addr);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement prep = connect.prepareStatement(removeQuery);) {
			prep.executeUpdate(removeQuery);
			connect.close();
		} catch (SQLException e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
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
				PreparedStatement prep = connect.prepareStatement(removeQuery);) {
			prep.executeUpdate(removeQuery);
			connect.close();
		} catch (Exception e) {
			//e.printStackTrace();
			throw new IllegalArgumentException(e);
		}
	}
}
