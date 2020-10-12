package net.floodlightcontroller.dpkmconfigurewg;

/** 
 * Object representing a peer connection between switch A and switch B. </br>
 * Stores useful information during a number of peer related procedures. 
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmPeers {
	public int cid;
	public String dpidA;
	public String ipv4AddrA;
	public String ipv4AddrWGA;
	public String dpidB;
	public String ipv4AddrB;
	public String ipv4AddrWGB;
	public String status;
	
	public DpkmPeers() {
		this.cid = 0;
		this.dpidA = "";
		this.ipv4AddrA = "";
		this.ipv4AddrWGA = "";
		this.dpidB = "";
		this.ipv4AddrB = "";
		this.ipv4AddrWGB = "";
		this.status = "";
	}
}
