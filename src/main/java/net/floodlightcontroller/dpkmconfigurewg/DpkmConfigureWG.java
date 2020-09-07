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
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.projectfloodlight.openflow.protocol.OFDpkmAddPeer;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

public class DpkmConfigureWG implements IFloodlightModule, IDpkmConfigureWGService, IOFMessageListener, IOFSwitchListener {
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

	@Override
	public void switchAdded(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchDeactivated(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx){
		switch(msg.getType()) {
		    case EXPERIMENTER:
		    	OFDpkmHeader inExperimenter = (OFDpkmHeader) msg;
		        
		    	//if(inExperimenter.getSubtype() == 7 && testcount2 <= 3) {
		    		//try {
						//testcount2++;
		    			//processTestRequest(sw, (OFDpkmTestRequest)msg);
					//} catch (IOException e) {
						// TODO Auto-generated catch block
						//e.printStackTrace();
					//}
		    		//break;
		    	//}
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
	
	private void processStatusMessage(IOFSwitch sw, OFDpkmStatus msg) throws IOException {
		System.out.println("Status msg received.");
		try {
			// This statement is executed if WireGuard has been configured successfully.
	        if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_CONFIGURED) {
	        	if(checkIPExists(msg.getIpv4Addr()).equals("0")) {
	        		writeSwitchToDB(msg, sw);
	        		if(checkConfigured() >= 2) {
	        			constructAddPeerMessage(sw, msg.getIpv4Addr());
	        		}
	        		else if(checkConfigured() == 1) {
	        			System.out.println("No Peers to be added. ");
	        		} else {
	        			System.out.println("Error adding peer.");
	        		}
	        	} 
	        	else if(checkIPExists(msg.getIpv4Addr()).equals("Error")) {
	        		System.out.println("Error adding switch to DB.");
	        	} else {
	        		updateSwitchInDB(msg,sw);
	        		if(checkConfigured() >= 2 && checkConnectedAny(msg) == 0) {
	        			constructAddPeerMessage(sw, msg.getIpv4Addr());
	        		}
	        		else if(checkConnectedAny(msg) >= 1) {
	        			constructDeletePeerMessage(sw, msg.getIpv4Addr(), false);
	        		}
	        		else if(checkConfigured() == 1) {
	        			System.out.println("No other nodes in the DB.");
	        		}
	        	}
			}
	        // This statement is executed if a peer has been added successfully.
	        if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_ADDED) {
	        	if(checkConnected(msg) == 0) {
	        		addPeerConnection(msg);
	        		IOFSwitch targetSW = switchService.getSwitch(DatapathId.of(getDpId(msg.getIpv4Peer())));
        			constructAddPeerMessage(targetSW, msg.getIpv4Peer());
	        	}
	        	else if(checkConnected(msg) >= 1) {
	        		updatePeerInfo(msg);
	        	} else {
	        		System.out.println("An error occurred adding peer info to DB.");
	        	}
	        }
	        // This statement is executed if a peer has been deleted successfully. 
	        if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_REMOVED) {
	        	if(checkConnectedAny(msg) >= 1) {
	        		IOFSwitch targetSW = switchService.getSwitch(DatapathId.of(getDpId(msg.getIpv4Peer())));
	        		constructDeletePeerMessage(targetSW, msg.getIpv4Peer(), true);
	        		removePeerConnection(msg);
	        	}
	        	constructAddPeerMessage(sw, msg.getIpv4Addr());
	        }
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
            //close();
        }
		
	}
	
	@Override
	public void sendSetKeyMessage(DatapathId dpid, int cryptoperiod) {
		System.out.println("Sendsetkeymessage has been called.");
		IOFSwitch sw = switchService.getSwitch(dpid);
		currentCryptoperiod = cryptoperiod;
		try {
			OFDpkmSetKey setKeyMsg = sw.getOFFactory().buildDpkmSetKey()
					.build();
			
			sw.write(setKeyMsg);
		}
		catch(Exception e) {
			System.out.println("NullPointerException Thrown!");
			log.error("Unable to send DPKM_SET_KEY message.");
		}
	}
	@Override
	public List<DpkmSwitch> getSwitches() {
		String getSQL = "SELECT * FROM cntrldb.ConfiguredPeers;";
		ArrayList<DpkmSwitch> confSwitches = new ArrayList<DpkmSwitch>();
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement get = connect.prepareStatement(getSQL);) {
			boolean isResult = get.execute();
			do {
				try (ResultSet rs = get.getResultSet()) {
	    			while (rs.next()) {
	    				DpkmSwitch cSwitch = new DpkmSwitch();
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
	@Override
	public List<DpkmPeers> getPeers() {
		String getSQL = "SELECT ConfiguredPeer1.Dpid as 'Dpid1', ConfiguredPeer1.IPv4Addr as 'IPv4Addr1', "
				+ "ConfiguredPeer1.IPv4AddrWG as 'IPv4AddrWG1', ConfiguredPeer2.Dpid as 'Dpid2', "
				+ "ConfiguredPeer2.IPv4Addr as 'IPv4Addr2', ConfiguredPeer2.IPv4AddrWG as 'IPv4AddrWG2', "
				+ "CommunicatingPeers.Status FROM CommunicatingPeers  "
				+ "LEFT JOIN (ConfiguredPeers as ConfiguredPeer1) ON (CommunicatingPeers.PID1 = ConfiguredPeer1.id) "
				+ "LEFT JOIN (ConfiguredPeers as ConfiguredPeer2) ON (CommunicatingPeers.PID2 = ConfiguredPeer2.id) "
				+ "ORDER BY CommunicatingPeers.Cid;";
		ArrayList<DpkmPeers> confPeers = new ArrayList<DpkmPeers>();
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement get = connect.prepareStatement(getSQL);) {
			boolean isResult = get.execute();
			do {
				try (ResultSet rs = get.getResultSet()) {
	    			while (rs.next()) {
	    				DpkmPeers cPeer = new DpkmPeers();
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
	private void constructAddPeerMessage(IOFSwitch sw, String ipv4addr) throws SQLException {
		String getCred = String.format("SELECT PubKey1, IPv4Addr, IPv4AddrWG "
				+ "FROM cntrldb.ConfiguredPeers WHERE Status='CONFIGURED' AND IPv4Addr != '%s';", ipv4addr);
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement peerInfo = connect.prepareStatement(getCred);) {
			boolean isResult = peerInfo.execute();
	    	do {
	    		try (ResultSet rs = peerInfo.getResultSet()) {
	    			while (rs.next()) {
	    				sendAddPeerMessage(sw, rs.getString("PubKey1"),rs.getString("IPv4Addr"),rs.getString("IPv4AddrWG"));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		}
	}
	
	private void sendAddPeerMessage(IOFSwitch sw, String peerPubKey, String peerIPv4, String peerIPv4WG) {
		System.out.println("SendAddPeerMessage has been called.");
		try {
		    OFDpkmAddPeer addPeerMsg = sw.getOFFactory().buildDpkmAddPeer()
				    .setKey(peerPubKey)
				    .setIpv4Addr(peerIPv4)
				    .setIpv4Wg(peerIPv4WG)
				    .build();
		    sw.write(addPeerMsg);
		}
		catch(NullPointerException e) {
			System.out.println("NullPointerException Thrown at sendAddPeerMessage.");
		}
	}
	
	private void constructDeletePeerMessage(IOFSwitch sw, String ipv4addr, boolean newKey) throws SQLException {
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
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement peerInfo = connect.prepareStatement(getCred);) {
			boolean isResult = peerInfo.execute();
	    	do {
	    		try (ResultSet rs = peerInfo.getResultSet()) {
	    			while (rs.next()) {
	    				sendDeletePeerMessage(sw, rs.getString(1),rs.getString(2),rs.getString(3));
	    			}
	    			isResult = peerInfo.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		}
	}
	
	private void sendDeletePeerMessage(IOFSwitch sw, String peerPubKey, String peerIPv4, String peerIPv4WG) {
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
	
	private String getDpId(String ipv4Addr) throws SQLException {
		String getDpidSQL = String.format("SELECT Dpid FROM ConfiguredPeers WHERE Status = 'CONFIGURED' AND IPv4Addr = '%s';",ipv4Addr);
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
	    	return("Error");
		}
	}
	
	private String checkIPExists(String ipv4Addr) throws SQLException {
		String checkIP = String.format("SELECT COUNT(*) FROM ConfiguredPeers WHERE IPv4Addr = '%s';",ipv4Addr);
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
	    	return("Error");
		}
	}
	
	private int checkConfigured() throws SQLException {
		String checkConf = ("SELECT COUNT(*) FROM ConfiguredPeers WHERE STATUS = 'CONFIGURED';");
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
	    	return -1;
		}
	}
	
	private int checkConnected(OFDpkmStatus msg) throws SQLException {
		String checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
				+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));",
				msg.getIpv4Addr(),msg.getIpv4Peer(),msg.getIpv4Peer(),msg.getIpv4Addr());
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
	
	private int checkConnectedAny(OFDpkmStatus msg) throws SQLException {
		String checkQ = String.format("SELECT COUNT(*) FROM CommunicatingPeers "
				+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));",
				msg.getIpv4Addr(),msg.getIpv4Addr());
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
	    	return -1;
		}
	}
	
	private void writeSwitchToDB(OFDpkmStatus msg, IOFSwitch sw) throws SQLException {
		String sql = "INSERT INTO cntrldb.ConfiguredPeers VALUES (default, ?, ?, ?, ? , ?, ?, ?, ?)";
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
		}
	}
	
	private void updateSwitchInDB(OFDpkmStatus msg, IOFSwitch sw) throws SQLException {
		String updateSwitch = ("UPDATE cntrldb.ConfiguredPeers SET Cryptoperiod=?, "
				+ "PubKey2=PubKey1, PubKey1=?,Status=?,Compromised=?, IPv4AddrWG=?, Dpid=? WHERE IPv4Addr=?");
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
		}
	}
	
	private void addPeerConnection(OFDpkmStatus msg) throws SQLException {
		String addPeerQuery = String.format("INSERT INTO cntrldb.CommunicatingPeers(Cid,PID1,PID2,Status) "
				+ "VALUES(default,(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),"
				+ "(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'),'PID1ONLY');", 
				msg.getIpv4Addr(),msg.getIpv4Peer());
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement addPeer = connect.prepareStatement(addPeerQuery);) {
			addPeer.executeUpdate(addPeerQuery);
			connect.close();
		}
	}
	
	private void updatePeerInfo(OFDpkmStatus msg) throws SQLException {
		String updateQuery = String.format("UPDATE cntrldb.CommunicatingPeers SET Status='CONNECTED'"
				+ "WHERE (PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s')) OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
				msg.getIpv4Addr(), msg.getIpv4Peer(), msg.getIpv4Peer(), msg.getIpv4Addr());
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement updateCon = connect.prepareStatement(updateQuery);) {
			updateCon.executeUpdate(updateQuery);
			connect.close();
		}
	}
	
	private void removePeerConnection(OFDpkmStatus msg) throws SQLException {
		String removeQuery = String.format("DELETE FROM cntrldb.CommunicatingPeers WHERE "
				+ "PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') OR "
				+ "(PID1=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s') AND "
				+ "PID2=(SELECT id FROM ConfiguredPeers WHERE IPv4Addr='%s'));", 
				msg.getIpv4Addr(), msg.getIpv4Peer(), msg.getIpv4Peer(), msg.getIpv4Addr());
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement removeCon = connect.prepareStatement(removeQuery);) {
			removeCon.executeUpdate(removeQuery);
			connect.close();
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
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.EXPERIMENTER, this);
        switchService.addOFSwitchListener(this);
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
