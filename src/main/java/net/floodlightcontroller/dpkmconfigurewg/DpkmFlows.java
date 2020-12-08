package net.floodlightcontroller.dpkmconfigurewg;

import java.util.ArrayList;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowModify;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionClearActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U8;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	protected static Logger log = 
			LoggerFactory.getLogger(DpkmConfigureWGResource.class);
	
	/** 
	 * Constructs a FLOW_ADD message for directing any packets received by peerA
	 * destined to peerB through the port containing the WG interface.</br>
	 * Sets flow match conditions and actions/instructions to apply to packet.</br>
	 * Currently a work in progress and only matches on IP packets because
	 * Wireguard operates on L3.  
	 * @param peerA IOFSwitch instance of a switch A.
	 * @param peerB IOFSwitch instance of a switch B.
	 * @return OFFlowAdd message with flow targeting peerA and peerB.
	 */
	public OFFlowAdd constructFlowAdd(IOFSwitch peerA, IOFSwitch peerB) {
		String ipv4B = getIp(peerB.getId().toString(),false);
		// Create match conditions for switch.
		Match dpkmMatch = peerA.getOFFactory().buildMatch()
				.setExact(MatchField.DPKM_METHOD, U8.of((short) 1))
				.setExact(MatchField.IN_PORT, OFPort.LOCAL)
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setExact(MatchField.IPV4_DST, IPv4Address.of(ipv4B))
				.build();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		OFActions actions = peerA.getOFFactory().actions();
		OFOxms oxms = peerA.getOFFactory().oxms();
		// Modify ipv4 source field in packet to be WG source address.
		OFActionSetField setIpSrc = actions.buildSetField()
				.setField(
						oxms.buildIpv4Src()
						.setValue(IPv4Address
								.of(getIp(peerA.getId().toString(),true)))
						.build()).build();
		actionList.add(setIpSrc);
		// Modify ipv4 destination field in packet to be WG destination address.
		OFActionSetField setIpDst = actions.buildSetField()
				.setField(
						oxms.buildIpv4Dst()
						.setValue(IPv4Address
								.of(getIp(peerB.getId().toString(),true)))
						.build()).build();
		actionList.add(setIpDst);
		// Set action as output aka output on WireGuard port.
		OFActionOutput output = actions.buildOutput()
				.setMaxLen(0xffFFffFF)
				.setPort(OFPort.of(1))
				.build();
		actionList.add(output);
		
		// Write instruction to apply action list to packet on switch end.
		OFInstructionApplyActions applyActions = peerA.getOFFactory()
				.instructions().buildApplyActions()
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
				.setPriority(32768)
				.setMatch(dpkmMatch)
				.setInstructions(instructionList)
				.build();
		return flow;
	}
	
	/** 
	 * Constructs a FLOW_MOD message for modifying an existing flow to 
	 * drop any packets on peerA destined to peerB. 
	 * @param peerA IOFSwitch instance of a switch A.
	 * @param peerB IOFSwitch instance of a switch B.
	 * @return OFFlowModify message dropping packets between peerA and peerB.
	 */
	protected OFFlowModify constructFlowDrop(IOFSwitch peerA, IOFSwitch peerB) {
		// Instruction to clear action list on switch end, dropping packet.
		OFInstructionClearActions clearActions = peerA.getOFFactory()
				.instructions().clearActions();
		ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
		instructionList.add(clearActions);
		// Recreate identical flow to the existing.
		OFFlowAdd flow = constructFlowAdd(peerA, peerB);
		// Use the flow as a builder to update instruction. 
		OFFlowAdd newFlow = flow.createBuilder()
				.setInstructions(instructionList)
				.build();
				
		OFFlowModify flowModify = FlowModUtils.toFlowModify(newFlow);
		return flowModify;
	}
	
	/** 
	 * Constructs a FLOW_MOD message for changing an existing flow and 
	 * routing any packets on peerA destined to peerB via the controller.</br>
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
				.setPort(OFPort.CONTROLLER)
				.build();
		actionList.add(output);
		// Write instruction to apply action list to packet on switch end.
		OFInstructionApplyActions applyActions = peerA.getOFFactory()
				.instructions().buildApplyActions()
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
	
	/** 
	 * Handler for rekeying procedure. Before procedure packets are 
	 * redirected to standard port so are temporarily unencrypted.</br>
	 * After procedure the flow is restored.   
	 * @param peerA IOFSwitch instance of a switch A.
	 * @param peerB IOFSwitch instance of a switch B.
	 * @param before Boolean indicator of rekeying state (before/after).
	 */
	protected void handleFlowRekeying(IOFSwitch peerA, IOFSwitch peerB, 
			boolean before) {
		
		if(before) {
			OFFlowModify flowA = constructFlowModify(peerA,peerB);
			OFFlowModify flowB = constructFlowModify(peerB,peerA);
			peerA.write(flowA);
			peerB.write(flowB);
			log.warn(String.format(
					"Communication between switch %s and switch %s temporarily unencrypted.",
					peerA.getId().toString(),peerB.getId().toString()));
		} else {
			OFFlowAdd flowAddA = constructFlowAdd(peerA,peerB);
			OFFlowAdd flowAddB = constructFlowAdd(peerB,peerA);
			OFFlowModify flowA = FlowModUtils.toFlowModify(flowAddA);
			OFFlowModify flowB = FlowModUtils.toFlowModify(flowAddB);
			peerA.write(flowA);
			peerB.write(flowB);
			log.info(String.format(
					"Communication between switch %s and switch %s restored.",
					peerA.getId().toString(),peerB.getId().toString()));
		}
	}
}


