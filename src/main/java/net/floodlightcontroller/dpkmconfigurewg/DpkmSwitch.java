package net.floodlightcontroller.dpkmconfigurewg;

/** 
 * Object representing a single switch in the DPKM protocol. </br>
 * Stores useful information during a number of switch related procedures. 
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmSwitch {
	public int id;
	public String dpid;
	public String ipv4Addr;
	public String ipv4AddrWG;
    public int cryptoperiod;
    public String status;
    public boolean compromised;
    public String since;
    
    public DpkmSwitch() {
    	this.id = 0;
    	this.dpid = "";
    	this.ipv4Addr = "";
    	this.ipv4AddrWG = "";
    	this.cryptoperiod = 0;
    	this.status = "";
    	this.compromised = false;
    	this.since = "";
    }
}
