package net.floodlightcontroller.dpkmconfigurewg;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * Provides a connection to the underlying DPKM database using the credentials
 * stored in the db.properties file. </br>
 * 
 * @author Luke Hengstenberg
 * @version 1.0
 */
public class ConnectionProvider {
	protected static Logger log = LoggerFactory.getLogger(DpkmConfigureWG.class);
	static Properties prop = getCredentials();
    private static final String url = prop.getProperty("db.url");
    private static final String user = prop.getProperty("db.user");
    private static final String password = prop.getProperty("db.password");
    /**  
	 * @return Connection object from DriverManager or null.
	 * @exception Exception if connecting to db fails.
	 */
    public static Connection getConn() {
    	try {
    		return DriverManager.getConnection(url, user, password);
    	} catch(SQLException e) {
    		log.error("Failed to get connection to db.");
    		return null;
    	}
    }
    /**  
	 * @return Properties object with credentials stored in db.properties file.
	 * @exception IOException if accessing properties file fails.
	 */
    private static Properties getCredentials() {
		Properties prop = new Properties();
		try (FileInputStream in 
				= new FileInputStream("src/main/resources/db.properties")){
			prop.load(in);
		} catch (IOException e) {
			log.error("Failed to access properties file.");
		}
		return prop;
	}
}
