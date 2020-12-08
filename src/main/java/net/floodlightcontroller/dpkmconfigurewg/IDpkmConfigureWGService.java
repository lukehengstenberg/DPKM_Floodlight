package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.SQLException;
import java.util.List;

import org.projectfloodlight.openflow.types.DatapathId;

import net.floodlightcontroller.core.module.IFloodlightService;

/** 
 * Defines the abstract functions for configuring WireGuard and provides a service
 * for linking the REST APIs to methods in the module dpkmconfigurewg. </br>
 * Important interface to add services to the underlying module through extending
 * the base IFloodlightService class. 
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public interface IDpkmConfigureWGService extends IFloodlightService {
    
	/** 
	 * Returns a full list of configured switches from the db, mapping fields
	 * to DpkmSwitch objects. 
	 * @return List<DpkmSwitch> List of WG switches in db.
	 * @exception SQLException if SQL query to db fails.
	 * @see DpkmConfigureWG#getSwitches() 
	 */
	public List<DpkmSwitch> getSwitches ();
	
	/** 
	 * Writes a DPKM_SET_KEY message to the switch with the given dpid,
	 * and sets the cryptoperiod.</br>
	 * This triggers the switch to generate the keys, configuring its
	 * WireGuard interface, returning a DPKM_STATUS or error response message. 
	 * @param dpid DatapathId of the switch. 
	 * @param cryptoperiod Valid cryptoperiod (seconds) before rekeying.
	 * @exception Exception if sending set key message fails.
	 * @see DpkmConfigureWG#sendSetKeyMessage(DatapathId, int)  
	 */
    public void sendSetKeyMessage (DatapathId dpid, int cryptoperiod);
    
    /** 
	 * Writes a DPKM_DELETE_KEY message to the switch with the given dpid. </br>
	 * This triggers the switch to delete its keys, unconfiguring WireGuard,
	 * returning a DPKM_STATUS or error response message.
	 * @param dpid DatapathId of the switch.
	 * @exception Exception if sending delete key message fails.
	 * @see DpkmConfigureWG#sendDeleteKeyMessage(DatapathId)  
	 */
    public void sendDeleteKeyMessage (DatapathId dpid);
    
    /** 
	 * Returns a full list of peers from the db, mapping fields
	 * to DpkmPeers objects. 
	 * @return List<DpkmPeers> List of WG peers in db.
	 * @exception SQLException if SQL query to db fails.
	 * @see DpkmConfigureWG#getPeers() 
	 */
    public List<DpkmPeers> getPeers ();
    
    /** 
	 * Returns count of peer connections using SQL queries based on statusType 
	 * or -1 if error. </br>
	 * Default: count of connections between ipv4AddrA and ipv4AddrB. </br>
	 * Used internally for a number of conditional statements.  
	 * @param ipv4AddrA IPv4 Address of a switch 'A'.
	 * @param ipv4AddrB IPv4 Address of a switch 'B'.
	 * @param statusType String used as a flag. 
	 * @return int Connection count or error (-1).
	 * @exception SQLException if SQL query to db fails.
	 * @see Dpkm#checkConnected(String, String, String)
	 */
    public int checkConnected(String ipv4AddrA, String ipv4AddrB, String statusType);
    
    /** 
	 * Writes a DPKM_ADD_PEER message to the switch with the given source dpid,
	 * adding the switch with the given target dpid as a peer.</br>
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch adding the peer. 
	 * @param targetDpid DatapathId of the switch to be added as a peer.
	 * @exception SQLException if SQL query to db fails.
	 * @see DpkmConfigureWG#sendAddPeerMessage(String, String)  
	 */
    public void sendAddPeerMessage(String sourceDpid, String targetDpid);
    
    /** 
	 * Writes a DPKM_DELETE_PEER message to the switch with the given source dpid,
	 * removing the switch with the given target dpid as a peer.</br>
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch removing the peer. 
	 * @param targetDpid DatapathId of the switch to be removed as a peer.
	 * @param keyChange Boolean specifying if the key has changed. 
	 * @exception SQLException if SQL query to db fails.
	 * @see DpkmConfigureWG#sendDeletePeerMessage(String, String, boolean) 
	 */
    public void sendDeletePeerMessage(String sourceDpid, String targetDpid, boolean keyChange);
    
    /** 
	 * Writes a FLOW_MOD message to both peer switches to push traffic through WG
	 * interface in port in accordance to the created flow table entry.</br>
	 * Enables packets to be encrypted/decrypted and sent between the interfaces.   
	 * @param dpidA DatapathId of peer (switch) A. 
	 * @param dpidB DatapathId of peer (switch) B.
	 * @exception Exception if sending flow mod message fails.
	 * @see DpkmConfigureWG#startCommunication(String, String)  
	 */
    public void startCommunication(String dpidA, String dpidB);
    
    /** 
	 * Writes a FLOW_MOD message to both peer switches to terminate communication
	 * entirely or continue communication unencrypted (not through WG). </br>
	 * This is decided by the administrator using the top level UI to set endType.   
	 * @param dpidA DatapathId of peer (switch) A. 
	 * @param dpidB DatapathId of peer (switch) B.
	 * @param endType Type of termination (all communication or WG only). 
	 * @see DpkmConfigureWG#endCommunication(String, String, String) 
	 */
    public void endCommunication(String dpidA, String dpidB, String endType);
    
    /** 
	 * Rekey's the switch after expiry of the given cryptoperiod.</br>
	 * This consists of reconfiguring the switch using a DPKM_SET_KEY message.   
	 * @param dpid DatapathId of the switch. 
	 * @param cryptoperiod Life span of the key in seconds.
	 * @exception Exception if any messages sent during rekeying fail.
	 * @see DpkmConfigureWG#rekey(String, int)  
	 */
    public void rekey(String dpid, int cryptoperiod);
    
    /** 
	 * Compromises switch with id to trigger the revocation procedure.</br>
	 * This updates the db record and ends all communication with the switch.  
	 * @param id Integer value of switch record in db.
	 * @see DpkmConfigureWG#compromiseNode(int)   
	 */
    public void compromiseNode(int id);
    
    /** 
	 * Returns boolean compromised for the switch with dpid. 
	 * @param dpid DatapathId of the switch.
	 * @return boolean value in compromised field of switch or true by default 
	 * 		   to prevent actions against non-existent switch.
	 * @exception SQLException if SQL query to db fails.
	 * @see Dpkm#checkCompromised(String)
	 */
    public boolean checkCompromised(String dpid);
    
    /** 
	 * Carries out the revocation procedure for a compromised switch dpid.</br>
	 * Based on the top-level policy this means reconfiguring the switch with 
	 * a SET_KEY message or terminating the switch with a DELETE_KEY message.
	 * @param dpid DatapathId of the switch.
	 * @param revType Revocation type either reconfigure or terminate switch.
	 * @see DpkmConfigureWG#revoke(String, String)   
	 */
    public void revoke(String dpid, String revType);
    
    /** 
	 * Returns unresolved error count for switch with DatapathId dpid.</br>
	 * Used internally for a number of conditional statements.  
	 * @param dpid DatapathId of a switch in string format.
	 * @return int Error count or -1.
	 * @exception SQLException if SQL query to db fails.
	 * @see Dpkm#checkError(String)
	 */
    public int checkError(String dpid);
}
