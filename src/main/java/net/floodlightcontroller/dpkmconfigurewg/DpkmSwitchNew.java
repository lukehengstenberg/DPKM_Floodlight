package net.floodlightcontroller.dpkmconfigurewg;

import org.projectfloodlight.openflow.types.DatapathId;

import net.floodlightcontroller.core.IOFSwitch;

public class DpkmSwitchNew {
    public DatapathId dpid;
    public int cryptoperiod;
    
    public DpkmSwitchNew() {
    	this.dpid = DatapathId.NONE;
    	this.cryptoperiod = 0;
    }
    public DatapathId getDpid() {
    	return dpid;
    }
    public int getCryptoperiod() {
    	return cryptoperiod;
    }
     
}
