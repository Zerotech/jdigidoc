package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;

import ee.sk.digidoc.DigiDocException;

public interface CAService {

    boolean verifyCertificate(X509Certificate cert) throws DigiDocException;
    
    X509Certificate findCAforCertificate(X509Certificate cert);
}
