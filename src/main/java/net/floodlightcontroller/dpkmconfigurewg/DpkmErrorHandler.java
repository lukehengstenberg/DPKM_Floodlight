package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFDpkmAddPeer;
import org.projectfloodlight.openflow.protocol.OFDpkmDeletePeer;
import org.projectfloodlight.openflow.protocol.OFDpkmHeader;
import org.projectfloodlight.openflow.protocol.OFDpkmStatus;
import org.projectfloodlight.openflow.protocol.OFDpkmStatusFlag;
import org.projectfloodlight.openflow.protocol.OFErrorType;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmBaseError;
import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmDecodeAddPeerError;
import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmDecodeDeletePeerError;
import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmExecuteAddPeerError;
import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmExecuteDeletePeerError;
import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmGetIpSError;
import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmGetKeyError;
import org.projectfloodlight.openflow.types.OFErrorCauseData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.restserver.IRestApiService;

/** 
 * Module responsible for handling all errors related to the 
 * Data Plane Key Management protocol. </br>
 * Version 1.0 of DPKM has a total of 15 error messages which are handled here. </br>
 * When an error is sent by a switch in response to a DPKM message this class
 * logs the error and resends the same message several times in case the error 
 * occurred due to some unique circumstance. </br> 
 * If the maximum number of retries is reached this class disconnects the switch
 * until the error has been addressed externally by the administrator.
 * 
 * @author Luke Hengstenberg 
 * @version 1.0
 */
public class DpkmErrorHandler extends DpkmError implements IFloodlightModule, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(DpkmErrorHandler.class);
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected IDpkmConfigureWGService confWGService;
	
	@Override
	public String getName() {
		return "DpkmErrorHandler";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// After checking DPKM messages pass them on to the DpkmConfigureWG module. 
		return (type.equals(OFType.EXPERIMENTER) && 
				(name.equalsIgnoreCase("DpkmConfigureWG")));
	}
	
	/** 
	 * Implements a message listener for messages of type EXPERIMENTER and ERROR. </br>
	 * Only interested in DPKM_STATUS (subtype 5) experimenter messages as an
	 * indicator that the message is now returning as expected. </br>
	 * Listens for all DPKM error messages and passes on to the processing method.  
	 * @param sw Instance of a switch connected to the controller.
	 * @param msg The received OpenFlow message.
	 * @param cntx Floodlight context for registering the listener. 
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch(msg.getType()) {
			case EXPERIMENTER:
				// Cast the message to a DPKM OpenFlow experimenter message.
		    	OFDpkmHeader inExperimenter = (OFDpkmHeader) msg;
		    	// Subtype 5 means a status message has been received and should be processed. 
		    	if(inExperimenter.getSubtype() == 5) {
		    		if(checkError(sw.getId().toString()) > 0) {
		    			processResponseMessage(sw.getId().toString(), (OFDpkmStatus)msg);
		    		}
		    		break;
		    	}
		    	else {
		    		// Ignore other DPKM messages.
		    		break;
		    	}
			case ERROR:
				// Cast the message to a DPKM OpenFlow error message.
				OFDpkmBaseError inError = (OFDpkmBaseError) msg;
				// Only handle DPKM related error messages here. 
				if(inError.getErrType() == OFErrorType.EXPERIMENTER) {
					processErrorMessage(sw, inError);
				} else {
					log.error("An error unrelated to DPKM occurred. See log for "
							+ "details.");
				}
				break;
			default:
				break;
		}
		return Command.CONTINUE;
	}
	
	/** 
	 * Processes the status message sent by the switch based on the status flag.</br>
	 * Resolves errors based on type of status response indicating that the message
	 * is returning as expected.
	 * @param dpid DatapathId of a switch connected to the controller.
	 * @param msg The received OpenFlow DPKM Status message. 
	 */
	private void processResponseMessage(String dpid, OFDpkmStatus msg) {
		// Executed if the status response shows WG has been configured.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_CONFIGURED) {
			resolveError(dpid, "SET_KEY");
		}
		// Executed if the status response shows a peer has been added.
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_ADDED) {
			resolveError(dpid, "ADD_PEER");
		}
		// Executed if the status response shows a peer has been deleted. 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_PEER_REMOVED) {
			resolveError(dpid, "DELETE_PEER");
		}
		// Executed if the status response shows a key has been revoked (unconfigured). 
		if(msg.getStatusFlag() == OFDpkmStatusFlag.DPKM_STATUS_FLAG_REVOKED) {
			resolveError(dpid, "DELETE_KEY");
		} 
	}
	
	/** 
	 * Processes the error messages sent by the switch based on the subtype.</br>
	 * Has a total of 15 cases for the 15 DPKM error types.</br>
	 * Calls a handler method based on the type of error and desired strategy. 
	 * @param sw Instance of a switch connected to the controller.
	 * @param inError OFDpkmBaseError error message received from the switch.
	 */
	private synchronized void processErrorMessage(IOFSwitch sw, OFDpkmBaseError inError) {
		String errCode, note, ipv4Peer; 
		switch(inError.getSubtype()) {
			case 0:
				errCode = "DECODE_SET_KEY";
				note = "failed to decode a DPKM_SET_KEY message";
				handleErrorSetKey(sw, errCode, note);
				break;
			case 1:
				errCode = "DECODE_DELETE_KEY";
				note = "failed to decode a DPKM_DELETE_KEY message";
				handleErrorDeleteKey(sw, errCode, note);
				break;
			case 2:
				errCode = "DECODE_ADD_PEER";
				note = "failed to decode a DPKM_ADD_PEER message";
				ipv4Peer = extractIp(inError);
				handleErrorAddPeer(sw, errCode, note, ipv4Peer);
				break;
			case 3:
				errCode = "DECODE_DELETE_PEER";
				note = "failed to decode a DPKM_DELETE_PEER message";
				ipv4Peer = extractIp(inError);
				handleErrorDeletePeer(sw, errCode, note, ipv4Peer);
				break;
			case 4:
				handleErrorDecodeGetStatus(sw);
				break;
			case 5:
				errCode = "EXECUTE_SET_KEY";
				note = "failed to execute WG configuration script";
				handleErrorSetKey(sw, errCode, note);
				break;
			case 6:
				errCode = "EXECUTE_DELETE_KEY";
				note = "failed to execute WG unconfiguration script";
				handleErrorDeleteKey(sw, errCode, note);
				break;
			case 7:
				errCode = "EXECUTE_ADD_PEER";
				note = "failed to execute WG add peer script";
				ipv4Peer = extractIp(inError);
				handleErrorAddPeer(sw, errCode, note, ipv4Peer);
				break;
			case 8:
				errCode = "EXECUTE_DELETE_PEER";
				note = "failed to execute WG delete peer script";
				ipv4Peer = extractIp(inError);
				handleErrorDeletePeer(sw, errCode, note, ipv4Peer);
				break;
			case 9:
				errCode = "GET_KEY";
				note = "failed to retrieve the public key";
				handleErrorOther(sw, inError, errCode, note);
				break;
			case 10:
				errCode = "GET_IP_S";
				note = "failed to retrieve s1 ipv4 addr";
				handleErrorOther(sw, inError, errCode, note);
				break;
			case 11:
				errCode = "GET_IP_WG";
				note = "failed to retrieve WG ipv4 addr";
				handleErrorOther(sw, inError, errCode, note);
				break;
			case 12:
				errCode = "MISSING_KEY";
				note = "sent a message with missing public key";
				handleErrorOther(sw, inError, errCode, note);
				break;
			case 13:
				errCode = "MISSING_IP_S";
				note = "sent a message with missing ipv4 address";
				handleErrorOther(sw, inError, errCode, note);
				break;
			case 14:
				errCode = "MISSING_IP_WG";
				note = "sent a message with missing wg address";
				handleErrorOther(sw, inError, errCode, note);
				break;
			default:
				break;
		}
	}
	
	/** 
	 * Handles 
	 * @param sw Instance of a switch connected to the controller.
	 * @param inError OFDpkmBaseError error message received from the switch.
	 */
	private synchronized void handleErrorSetKey(IOFSwitch sw, String errCode, 
			String note) {
		String dpid = sw.getId().toString();
		String type = "SET_KEY";
		int attempt = checkAttempt(dpid,errCode);
		if(attempt >= 3) {
			note = String.format("MAX ATTEMPTS: Switch '%s' %s. Switch "
					+ "will be disconnected and must be repaired.", dpid,note);
			log.error(note);
			updateMaxAttempt(dpid, errCode, "ACTION NEEDED");
			//sw.disconnect();
		}
		else if(checkErrorCount(dpid,errCode) > 0) {
			log.error(String.format("Attempt %s: Switch '%s' %s", 
					attempt, dpid, note));
			updateAttempt(dpid,errCode);
			confWGService.sendSetKeyMessage(sw.getId(), 600);
		} else {
			logError(dpid, type, errCode, note);
			log.error(String.format("Switch '%s' %s", dpid, note));
			confWGService.sendSetKeyMessage(sw.getId(), 600);
		}
	}
	
	private synchronized void handleErrorDeleteKey(IOFSwitch sw, String errCode, 
			String note) {
		String dpid = sw.getId().toString();
		String type = "DELETE_KEY";
		int attempt = checkAttempt(dpid,errCode);
		if(attempt >= 3) {
			note = String.format("MAX ATTEMPTS: Switch '%s' %s. Switch "
					+ "will be disconnected and must be repaired.", dpid,note);
			log.error(note);
			updateMaxAttempt(dpid, errCode, "ACTION NEEDED");
			//sw.disconnect();
			removeSwitch(getIp(dpid,false));
		}
		else if(checkErrorCount(dpid,errCode) > 0) {
			log.error(String.format("Attempt %s: Switch '%s' %s", 
					attempt, dpid, note));
			updateAttempt(dpid,errCode);
			confWGService.sendDeleteKeyMessage(sw.getId());
		} else {
			logError(dpid, type, errCode, note);
			log.error(String.format("Switch '%s' %s", dpid, note));
			confWGService.sendDeleteKeyMessage(sw.getId());
		}
	}
	
	private synchronized void handleErrorAddPeer(IOFSwitch sw,  String errCode, 
			String note, String ipv4Peer) {
		String dpid = sw.getId().toString();
		String type = "ADD_PEER";
		int attempt = checkAttempt(dpid,errCode);
		String ipv4A = getIp(dpid,false);
		String peerDpid = getDpId(ipv4Peer,0,false);
		if(peerDpid.equalsIgnoreCase("Error")) {
			log.error(String.format("Failed to correctly handle %s error. "
					+ "See log for details.", errCode));
		}
		else if(attempt >= 3) {
			note = String.format("MAX ATTEMPTS: Switch '%s' %s. Switch "
					+ "will be disconnected and must be repaired.", dpid,note);
			log.error(note);
			updateMaxAttempt(dpid, errCode, "ACTION NEEDED");	
			if(checkConnected(ipv4A,ipv4Peer,4) > 0) {
				removePeerConnection(ipv4A,ipv4Peer);
			}
			else if(checkConnected(ipv4A,ipv4Peer,5) > 0) {
				removePeerConnection(ipv4A,ipv4Peer);
				confWGService.sendDeletePeerMessage(peerDpid, dpid, false);
			}
			//sw.disconnect();
			removeSwitch(ipv4A);
		}
		else if(checkErrorCount(dpid,errCode) > 0) {
			log.error(String.format("Attempt %s: Switch '%s' %s", 
					attempt, dpid, note));
			updateAttempt(dpid,errCode);
			if(checkConnected(ipv4A,ipv4Peer,4) > 0) {
				removePeerConnection(ipv4A,ipv4Peer);
				confWGService.sendAddPeerMessage(dpid, peerDpid);
			}
			else if(checkConnected(ipv4A,ipv4Peer,5) > 0) {
				updatePeerInfo(ipv4A,ipv4Peer,4);
				confWGService.sendAddPeerMessage(dpid, peerDpid);
			}
		} else {
			logError(dpid, type, errCode, note);
			log.error(String.format("Switch '%s' %s", dpid, note));
			confWGService.sendAddPeerMessage(dpid, peerDpid);
		}
	}
	
	private synchronized void handleErrorDeletePeer(IOFSwitch sw, String errCode, 
			String note, String ipv4Peer) {
		String dpid = sw.getId().toString();
		String type = "DELETE_PEER";
		int attempt = checkAttempt(dpid,errCode);
		String ipv4 = getIp(dpid,false);
		String peerDpid = getDpId(ipv4Peer,0,false);
		if(ipv4.equalsIgnoreCase("Error") || peerDpid.equalsIgnoreCase("Error")) {
			log.error(String.format("Failed to correctly handle %s error. "
					+ "See log for details.", errCode));
		}
		if(attempt >= 3) {
			note = String.format("MAX ATTEMPTS: Switch '%s' %s. Switch "
					+ "will be disconnected and must be repaired.", dpid,note);
			log.error(note);
			updateMaxAttempt(dpid, errCode, "ACTION NEEDED");
			//sw.disconnect();
			confWGService.sendDeletePeerMessage(peerDpid, dpid, false);
			removePeerConnection(ipv4,ipv4Peer);
			removeSwitch(ipv4);
		}
		else if(checkErrorCount(dpid,errCode) > 0) {
			log.error(String.format("Attempt %s: Switch '%s' %s", 
					attempt, dpid, note));
			updateAttempt(dpid,errCode);
			confWGService.sendDeletePeerMessage(dpid, peerDpid, false);
		} else {
			logError(dpid, type, errCode, note);
			log.error(String.format("Switch '%s' %s", dpid, note));
			confWGService.sendDeletePeerMessage(dpid, peerDpid, false);
		}
	}
	
	private synchronized void handleErrorOther(IOFSwitch sw, OFDpkmBaseError inError, 
			String errCode, String note) {
		String ipv4Peer;
		String msg = inError.getData().toString();
		String msgType = msg.substring(msg.indexOf("data=") + 7,
				msg.indexOf("Ver14"));
		if(msgType.equalsIgnoreCase("SetKey")) {
			handleErrorSetKey(sw, errCode, note);
		}
		else if(msgType.equalsIgnoreCase("AddPeer")) {
			ipv4Peer = extractIp(inError);
			handleErrorAddPeer(sw, errCode, note, ipv4Peer);
		}
		else if(msgType.equalsIgnoreCase("DeletePeer")) {
			if(errCode.equalsIgnoreCase("MISSING_IP_S")) {
				String key = msg.substring(msg.indexOf("key=") + 4,
						msg.indexOf(", ipv4Addr"));
				ipv4Peer = getIpFromKey(key);
				if(!ipv4Peer.equalsIgnoreCase("Error")) {
					handleErrorDeletePeer(sw, errCode, note, ipv4Peer);
				}
			} else {
				ipv4Peer = extractIp(inError);
				handleErrorDeletePeer(sw, errCode, note, ipv4Peer);
			}
		} 
	}
	
	private synchronized void handleErrorDecodeGetStatus(IOFSwitch sw) {
		// The GET_STATUS message is currently not in use in this project. 
	}
	
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IDpkmConfigureWGService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		this.floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        this.switchService = context.getServiceImpl(IOFSwitchService.class);
        this.confWGService = context.getServiceImpl(IDpkmConfigureWGService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.EXPERIMENTER, this);
		floodlightProvider.addOFMessageListener(OFType.ERROR, this);
	}

}
