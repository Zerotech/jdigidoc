package ee.sk.digidoc.services;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

/**
 * HTTP authenticator class for ocsp requests
 * 
 * @author Veiko Sinivee
 */
public class HttpAuthenticator extends Authenticator {
    
    private String username;
    private String passwd;
    
    public HttpAuthenticator(String username, String passwd) {
        this.username = username;
        this.passwd = passwd;
    }
    
    public PasswordAuthentication getPasswordAuthentication() {
        return new PasswordAuthentication(username, passwd.toCharArray());
    }
}
