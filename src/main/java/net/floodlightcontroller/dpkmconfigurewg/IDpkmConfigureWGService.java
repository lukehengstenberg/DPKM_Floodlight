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
    
	public List<DpkmSwitch> getSwitches ();
    public void sendSetKeyMessage (DatapathId dpid, int cryptoperiod);
    public List<DpkmPeers> getPeers ();
    public int checkConnected(String ipv4AddrA, String ipv4AddrB, boolean keyChange);
    public void sendAddPeerMessage(String sourceDpid, String targetDpid);
    public void sendDeletePeerMessage(String sourceDpid, String targetDpid);
}
