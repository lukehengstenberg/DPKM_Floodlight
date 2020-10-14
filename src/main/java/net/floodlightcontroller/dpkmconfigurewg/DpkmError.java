package net.floodlightcontroller.dpkmconfigurewg;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.projectfloodlight.openflow.protocol.errormsg.OFDpkmBaseError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * Internal functionality for the Dpkm error handler. </br>
 * Used to interact with the database after some error has been encountered.  
 * 
 * @author Luke Hengstenberg
 * @version 1.0
 */
public class DpkmError extends Dpkm{
	protected static Logger log = LoggerFactory.getLogger(DpkmErrorHandler.class);
	
	/** 
	 * Updates the database by inserting a new record into table ErrorLog for 
	 * an error that occurred at a switch dpid. 
	 * @param dpid DatapathId of the switch that reported the error.
	 * @param type DPKM message type that caused the error.
	 * @param errCode Error code identifying a specific error. 
	 * @param note Extra information about the error. 
	 */
	protected void logError(String dpid, String type, String errCode, String note) {
		String sql = "INSERT INTO cntrldb.ErrorLog VALUES (default, ?, ?, ?, ?, ?, ?)";
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(sql);) {
			// Dpid, Type, ErrCode, Attempt, Resolved, Note
	        writeDB.setString(1, dpid);
	        writeDB.setString(2, type);
	        writeDB.setString(3, errCode);
	        writeDB.setInt(4, 2);
	        writeDB.setBoolean(5, false);
	        writeDB.setString(6, note);
	        writeDB.executeUpdate();
	        connect.close();
		} catch (SQLException e) {
			e.printStackTrace();
			log.error("Failed to log error message in database.");
		}
	}
	
	/** 
	 * Counts the number of errors matching code errCode for switch dpid that have
	 * not been resolved. 
	 * @param dpid DatapathId of a switch.
	 * @param errCode Error code identifying a specific error. 
	 * @return error count or -1.  
	 */
	protected int checkErrorCount(String dpid, String errCode) {
		String checkQ = String.format("SELECT COUNT(*) FROM cntrldb.ErrorLog "
				+ "WHERE Dpid = '%s' AND ErrCode = '%s' AND Resolved = false;",
				dpid,errCode);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement checkConn = connect.prepareStatement(checkQ);) {
			boolean isResult = checkConn.execute();
	    	do {
	    		try (ResultSet rs = checkConn.getResultSet()) {
	    			while (rs.next()) {
	    				return(Integer.parseInt(rs.getString(1)));
	    			}
	    			isResult = checkConn.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			e.printStackTrace();
			log.error("Failed to log error message in database.");
		}
		return -1;
	}
	
	/** 
	 * Gets the number of attempts switch dpid has had at sending a message 
	 * causing error code errCode.</br>
	 * Used to implement a limit to the number of times the controller can
	 * resend a particular message.  
	 * @param dpid DatapathId of a switch.
	 * @param errCode Error code identifying a specific error. 
	 * @return number of attempts or -1.  
	 */
	protected int checkAttempt(String dpid, String errCode) {
		String checkQ = String.format("SELECT Attempt FROM cntrldb.ErrorLog "
				+ "WHERE Dpid = '%s' AND ErrCode = '%s' AND Resolved = false;",
				dpid,errCode);
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement checkConn = connect.prepareStatement(checkQ);) {
			boolean isResult = checkConn.execute();
	    	do {
	    		try (ResultSet rs = checkConn.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getInt(1));
	    			}
	    			isResult = checkConn.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			e.printStackTrace();
			log.error("Failed to log error message in database.");
		}
		return -1;
	}
	
	/** 
	 * Updates number of attempts for error errCode reported by switch dpid. </br>
	 * Increments Attempt by 1, used to record the number of retries.   
	 * @param dpid DatapathId of the switch that reported the error.
	 * @param errCode Error code identifying a specific error. 
	 */
	protected void updateAttempt(String dpid, String errCode) {
		String update = ("UPDATE cntrldb.ErrorLog SET Attempt = Attempt + 1 WHERE "
				+ "Dpid=? AND ErrCode=? AND Resolved = false");
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(update);) {
			writeDB.setString(1, dpid);
			writeDB.setString(2, errCode);
			writeDB.executeUpdate();
			connect.close();
		} catch (SQLException e) {
			e.printStackTrace();
			log.error("Failed to log error message in database.");
		}
	}
	
	/** 
	 * Called when the max number of attempts has been reached, updating the 
	 * note of a record to provide information to the administrator.    
	 * @param dpid DatapathId of the switch that reported the error.
	 * @param errCode Error code identifying a specific error.
	 * @param note Extra information about the error. 
	 */
	protected void updateMaxAttempt(String dpid, String errCode, String note) {
		String update = ("UPDATE cntrldb.ErrorLog SET Note = ? "
				+ "WHERE Dpid=? AND ErrCode=? AND Resolved = false");
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(update);) {
			writeDB.setString(2, dpid);
			writeDB.setString(3, errCode);
			writeDB.setString(1, note);
			writeDB.executeUpdate();
			connect.close();
		} catch (SQLException e) {
			e.printStackTrace();
			log.error("Failed to log error message in database.");
		}
	}
	
	/** 
	 * Called when an error has been resolved and some DPKM message is working
	 * as expected. </br>
	 * Updates resolved to true for all records of matching type.    
	 * @param dpid DatapathId of the switch that reported the error.
	 * @param type DPKM message type that previously caused an error.
	 */
	protected void resolveError(String dpid, String type) {
		String update = ("UPDATE cntrldb.ErrorLog SET Resolved = true, "
				+ "Note = 'RESOLVED' WHERE "
				+ "Dpid=? AND Type=? AND Resolved = false");
		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement writeDB = connect.prepareStatement(update);) {
			writeDB.setString(1, dpid);
			writeDB.setString(2, type);
			writeDB.executeUpdate();
			connect.close();
		} catch (SQLException e) {
			e.printStackTrace();
			log.error("Failed to log error message in database.");
		}
	}
	
	/** 
	 * Extracts the ipv4 address from an error message as a substring of the toString(). </br>
	 * Used to recreate the same add/delete peer message and retry.     
	 * @param inError OFDpkmBaseError received from the switch.
	 * @return ipv4 address extracted from the toString of version of the error message.  
	 */
	protected String extractIp(OFDpkmBaseError inError) {
		String msg = inError.getData().toString();
		String ipv4 = msg.substring(msg.lastIndexOf("ipv4Addr=") + 9, 
				msg.indexOf(", ipv4Wg"));
		return ipv4;
	}
	
	/** 
	 * Gets the IP address of a switch matching a specific public key. </br>
	 * Used in circumstances where an error is caused by a missing IP address.     
	 * @param key Public Key of a switch.
	 * @return ipv4 address of the switch with a matching public key or error.  
	 */
	protected String getIpFromKey(String key) {
		String getSQL = String.format("SELECT IPv4Addr FROM ConfiguredPeers WHERE "
				+ "PubKey1 = '%s' OR PubKey2 = '%s';",key,key);

		// Connects to the database and executes the SQL statement.
		try(Connection connect = ConnectionProvider.getConn();
				PreparedStatement getIp = connect.prepareStatement(getSQL);) {
			boolean isResult = getIp.execute();
	    	do {
	    		try (ResultSet rs = getIp.getResultSet()) {
	    			while (rs.next()) {
	    				return(rs.getString(1));
	    			}
	    			isResult = getIp.getMoreResults();
	    		}
	    	} while (isResult);
	    	connect.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
    	return("Error");
	}
	
}
