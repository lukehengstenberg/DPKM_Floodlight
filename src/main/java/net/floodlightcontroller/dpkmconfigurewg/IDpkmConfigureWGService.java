package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.projectfloodlight.openflow.types.DatapathId;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.SwitchMessagePair;
import net.floodlightcontroller.util.ConcurrentCircularBuffer;

public interface IDpkmConfigureWGService extends IFloodlightService {
    
	/** 
	 * Returns a full list of configured switches from the db, mapping fields
	 * to DpkmSwitch objects. 
	 * @return List<DpkmSwitch> List of WG switches in db. 
	 */
	public List<DpkmSwitch> getSwitches ();
	
	/** 
	 * Writes a DPKM_SET_KEY message to the switch with the given dpid,
	 * and sets the cryptoperiod.
	 * This triggers the switch to generate the keys, configuring its
	 * WireGuard interface, returning a DPKM_STATUS or error response message. 
	 * @param dpid DatapathId of the switch. 
	 * @param cryptoperiod Valid cryptoperiod (seconds) before rekeying.  
	 */
    public void sendSetKeyMessage (DatapathId dpid, int cryptoperiod);
    
    /** 
	 * Writes a DPKM_DELETE_KEY message to the switch with the given dpid.
	 * This triggers the switch to delete its keys, unconfiguring WireGuard,
	 * returning a DPKM_STATUS or error response message.
	 * @param dpid DatapathId of the switch.  
	 */
    public void sendDeleteKeyMessage (DatapathId dpid);
    
    /** 
	 * Returns a full list of peers from the db, mapping fields
	 * to DpkmPeers objects. 
	 * @return List<DpkmPeers> List of WG peers in db. 
	 */
    public List<DpkmPeers> getPeers ();
    
    /** 
	 * Returns count of peer connections using SQL queries based on statusType or -1 if error.
	 * Default: count of connections between ipv4AddrA and ipv4AddrB.
	 * statusType(1): count of connections with the status 'KEY CHANGED'.
	 * statusType(2): count of connections with the status 'REMOVED'.
	 * statusType(3): count of connections with the status 'COMMUNICATING'.
	 * statusType(4): count of connections with the status 'PID1ONLY'
	 * Used internally for a number of conditional statements.  
	 * @param ipv4AddrA IPv4 Address of a switch 'A'.
	 * @param ipv4AddrB IPv4 Address of a switch 'B'.
	 * @param statusType Integer used as a flag. 
	 * @return int Connection count or error (-1).
	 */
    public int checkConnected(String ipv4AddrA, String ipv4AddrB, int statusType);
    
    /** 
	 * Writes a DPKM_ADD_PEER message to the switch with the given source dpid,
	 * adding the switch with the given target dpid as a peer.
	 * This triggers the switch to add the peer info to its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch adding the peer. 
	 * @param targetDpid DatapathId of the switch to be added as a peer.  
	 */
    public void sendAddPeerMessage(String sourceDpid, String targetDpid);
    
    /** 
	 * Writes a DPKM_DELETE_PEER message to the switch with the given source dpid,
	 * removing the switch with the given target dpid as a peer.
	 * This triggers the switch to remove the peer info from its WireGuard interface, 
	 * returning a DPKM_STATUS or error response message. 
	 * @param sourceDpid DatapathId of the switch removing the peer. 
	 * @param targetDpid DatapathId of the switch to be removed as a peer.  
	 */
    public void sendDeletePeerMessage(String sourceDpid, String targetDpid, boolean keyChange);
    
    /** 
	 * Writes a FLOW_MOD message to both peer switches to push traffic through WG
	 * interface in port in accordance to the created flow table entry.
	 * This enables packets to be encrypted/decrypted and sent between the interfaces.   
	 * @param dpidA DatapathId of peer (switch) A. 
	 * @param dpidB DatapathId of peer (switch) B.  
	 */
    public void startCommunication(String dpidA, String dpidB);
    
    public void rekey(String dpid, int cryptoperiod);
}
