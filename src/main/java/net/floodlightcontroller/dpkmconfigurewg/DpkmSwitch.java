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
    public String pubKey1;
    public String pubKey2;
    
    public DpkmSwitch() {
    	this.id = 0;
    	this.dpid = "";
    	this.ipv4Addr = "";
    	this.ipv4AddrWG = "";
        this.cryptoperiod = 0;
        this.status = "";
        this.compromised = false;
        this.since = "";
        this.pubKey1 = "";
        this.pubKey2 = "";
    }
    
    public int getId() {
    	return id;
    }
    public void setId(int id) {
    	this.id = id;
    }
    public String getDpId() {
    	return dpid;
    }
    public void setDpId(String dpid) {
    	this.dpid = dpid;
    }
    public String getIpv4Addr() {
    	return ipv4Addr;
    }
    public void setIpv4Addr(String ipv4Addr) {
    	this.ipv4Addr = ipv4Addr;
    }
    public String getIpv4AddrWG() {
    	return ipv4AddrWG;
    }
    public void setIpv4AddrWG(String ipv4AddrWG) {
    	this.ipv4AddrWG = ipv4AddrWG;
    }
    public int getCryptoperiod() {
    	return cryptoperiod;
    }
    public void setCryptoperiod(int cryptoperiod) {
    	this.cryptoperiod = cryptoperiod;
    }
    public String getStatus() {
    	return status;
    }
    public void setStatus(String status) {
    	this.status = status;
    }
    public boolean getCompromised() {
    	return compromised;
    }
    public void setCompromised(boolean compromised) {
    	this.compromised = compromised;
    }
    public String getSince() {
    	return since;
    }
    public void setSince(String since) {
    	this.since = since;
    }
    public String getPubKey1() {
    	return pubKey1;
    }
    public void setPubKey1(String pubKey1) {
    	this.pubKey1 = pubKey1;
    }
    public String getPubKey2() {
    	return pubKey2;
    }
    public void setPubKey2(String pubKey2) {
    	this.pubKey2 = pubKey2;
    }
}
