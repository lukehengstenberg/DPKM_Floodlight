package net.floodlightcontroller.dpkmconfigurewg;


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
