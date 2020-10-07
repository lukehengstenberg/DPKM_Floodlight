package net.floodlightcontroller.dpkmconfigurewg;

import java.util.ArrayList;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowModify;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionPopVlan;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U8;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.util.FlowModUtils;

/** 
 * Flow configuration functionality of the Data Plane Key Management Protocol. </br>
 * Used for routing packets through WG interface, stopping packets from being sent
 * between switches, or redirecting packets through a different port. </br>
 * Class utilised by start communication, end communication, rekeying and revocation 
 * procedures.</br>
 * Work in progress. 
 * 
 * @author Luke Hengstenberg
 * @version 1.0
 */
public class DpkmFlows extends Dpkm{
	
	/** 
	 * Constructs a FLOW_ADD message for directing any packets received by peerA
	 * destined to peerB through the port containing the WG interface.
	 * Sets flow match conditions and actions/instructions to apply to packet.
	 * Currently a work in progress and not working as expected on switch end.  
	 * @param peerA IOFSwitch instance of a switch A.
	 * @param peerB IOFSwitch instance of a switch B.
	 * @return OFFlowAdd message with flow targeting peerA and peerB.
	 */
	public OFFlowAdd constructFlowAdd(IOFSwitch peerA, IOFSwitch peerB) {
		String ipv4A = getIp(peerA,false);
		String ipv4B = getIp(peerB,false);
		String hostA = "192.168.100.8";
		String hostB = "192.168.200.13";
		if(ipv4A.equalsIgnoreCase("192.168.0.13")) {
			hostA = "192.168.200.13";
			hostB = "192.168.100.8";
		} 
		// Create match conditions for switch.
		Match dpkmMatch = peerA.getOFFactory().buildMatch()
				//.setExact(MatchField.DPKM_METHOD, U8.of((short) 1))
				.setExact(MatchField.IN_PORT, OFPort.ANY)
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				//.setExact(MatchField.IPV4_SRC, IPv4Address.of(ipv4A))
				.setExact(MatchField.IPV4_DST, IPv4Address.of(hostB))
				//.setExact(MatchField.IP_PROTO, IpProtocol.ICMP)
				//.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
				//.setExact(MatchField.UDP_SRC, TransportPort.of(51820))
				//.setExact(MatchField.UDP_DST, TransportPort.of(51820))
				.build();
		
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		OFActions actions = peerA.getOFFactory().actions();
		OFOxms oxms = peerA.getOFFactory().oxms();
		// Modify data layer destination field in packet.
		//OFActionSetField setDlDst = actions.buildSetField()
				//.setField(
						//oxms.buildEthDst()
						//.setValue(MacAddress.of(peerB.getId()))
						//.build()).build();
		//actionList.add(setDlDst);
		// Modify ipv4 source field in packet to satisfy WG.
		OFActionSetField setIpSrc = actions.buildSetField()
				.setField(
						oxms.buildIpv4Src()
						.setValue(IPv4Address.of(getIp(peerA,true)))
						.build()).build();
		actionList.add(setIpSrc);
		// Modify ipv4 destination field in packet to satisfy WG.
		OFActionSetField setIpDst = actions.buildSetField()
				.setField(
						oxms.buildIpv4Dst()
						.setValue(IPv4Address.of(getIp(peerB,true)))
						.build()).build();
		actionList.add(setIpDst);
		// Modify udp source port in packet to satisfy WG.
		//OFActionSetField setUdpSrc = actions.buildSetField()
				//.setField(
						//oxms.buildUdpSrc()
						//.setValue(TransportPort.of(51820))
						//.build()).build();
		//actionList.add(setUdpSrc);
		// Modify udp destination port in packet to satisfy WG.
		//OFActionSetField setUdpDst = actions.buildSetField()
				//.setField(
						//oxms.buildUdpDst()
						//.setValue(TransportPort.of(51820))
						//.build()).build();
		//actionList.add(setUdpDst);
		//OFActionPopVlan popVlan = actions.popVlan();
		//actionList.add(popVlan);
		// Set action as output aka output to port.
		OFActionOutput output = actions.buildOutput()
				.setMaxLen(0xffFFffFF)
				.setPort(OFPort.of(1))
				.build();
		actionList.add(output);
		
		// Write instruction to apply action list to packet on switch end.
		OFInstructionApplyActions applyActions = peerA.getOFFactory().instructions().buildApplyActions()
				.setActions(actionList)
				.build();
		ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
		instructionList.add(applyActions);
		// Construct FLOW_ADD message with matches and actions/instructions.
		OFFlowAdd flow = peerA.getOFFactory().buildFlowAdd()
				.setOutPort(OFPort.of(1))
				.setBufferId(OFBufferId.NO_BUFFER)
				.setHardTimeout(0)
				.setIdleTimeout(0)
				.setPriority(20000)
				.setMatch(dpkmMatch)
				.setInstructions(instructionList)
				.build();
		return flow;
	}
	
	/** 
	 * Constructs a FLOW_DELETE message for removing an existing flow and 
	 * dropping any packets on peerA destined to peerB. 
	 * @param peerA IOFSwitch instance of a switch A.
	 * @param peerB IOFSwitch instance of a switch B.
	 * @return OFFlowDelete message deleting flow between peerA and peerB.
	 */
	protected OFFlowDelete constructFlowDelete(IOFSwitch peerA, IOFSwitch peerB) {
		// Recreate identical flow to the existing.
		OFFlowAdd flow = constructFlowAdd(peerA, peerB);
		// Convert to flow delete.
		OFFlowDelete flowDelete = FlowModUtils.toFlowDelete(flow);
		return flowDelete;
	}
	
	/** 
	 * Constructs a FLOW_MODIFY message for changing an existing flow and 
	 * routing any packets on peerA destined to peerB through the normal port.
	 * This means packets will not be encrypted and sent through WG. 
	 * @param peerA IOFSwitch instance of a switch A.
	 * @param peerB IOFSwitch instance of a switch B.
	 * @return OFFlowModify message modifying flow between peerA and peerB.
	 */
	protected OFFlowModify constructFlowModify(IOFSwitch peerA, IOFSwitch peerB) {
		// Create new actions for switch.
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		OFActions actions = peerA.getOFFactory().actions();
		// Set action to output via normal port.
		OFActionOutput output = actions.buildOutput()
				.setMaxLen(0xffFFffFF)
				.setPort(OFPort.LOCAL)
				.build();
		actionList.add(output);
		// Write instruction to apply action list to packet on switch end.
		OFInstructionApplyActions applyActions = peerA.getOFFactory().instructions().buildApplyActions()
				.setActions(actionList)
				.build();
		ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
		instructionList.add(applyActions);
		// Recreate identical flow to the existing.
		OFFlowAdd flow = constructFlowAdd(peerA, peerB);
		// Use the flow as a builder to update port. 
		OFFlowAdd newFlow = flow.createBuilder()
				.setInstructions(instructionList)
				.build();
				
		OFFlowModify flowModify = FlowModUtils.toFlowModify(newFlow);
		return flowModify;
	}
}


