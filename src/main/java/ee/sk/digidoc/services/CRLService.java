package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;
import java.util.Date;

import ee.sk.digidoc.DigiDocException;

public interface CRLService {

    void checkCertificate(X509Certificate cert, Date checkDate) throws DigiDocException;

}
