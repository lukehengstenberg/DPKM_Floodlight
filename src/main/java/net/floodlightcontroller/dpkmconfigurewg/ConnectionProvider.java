package net.floodlightcontroller.dpkmconfigurewg;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

public class ConnectionProvider {
	static Properties prop = getCredentials();
    private static final String url = prop.getProperty("db.url");
    private static final String user = prop.getProperty("db.user");
    private static final String password = prop.getProperty("db.password");
    public static Connection getConn() {
    	try {
    		return DriverManager.getConnection(url, user, password);
    	} catch(Exception e) {
    		System.out.println("Failed to get connection to db.");
    		return null;
    	}
    }
    private static Properties getCredentials() {
		Properties prop = new Properties();
		try (FileInputStream in = new FileInputStream("src/main/resources/db.properties")){
			prop.load(in);
		} catch (IOException e) {
			System.out.println("Failed to access properties file.");
		}
		return prop;
	}
}
