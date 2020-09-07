package net.floodlightcontroller.dpkmconfigurewg;


public class DpkmSwitch {
	public String dpid;
	public String ipv4Addr;
	public String ipv4AddrWG;
    public int cryptoperiod;
    public String status;
    public boolean compromised;
    
    public DpkmSwitch() {
    	this.dpid = "";
    	this.ipv4Addr = "";
    	this.ipv4AddrWG = "";
    	this.cryptoperiod = 0;
    	this.status = "";
    	this.compromised = false;
    }
}
