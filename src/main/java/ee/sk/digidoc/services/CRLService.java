package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;
import java.util.Date;

import ee.sk.digidoc.DigiDocException;

public interface CRLService {
    
    /**
     * Checks the cert
     * 
     * @return void
     * @param cert cert to be verified
     * @param checkDate java.util.Date
     * @throws DigiDocException for all errors
     */
    public void checkCertificate(X509Certificate cert, Date checkDate) throws DigiDocException;
    
    /**
     * Check cert by crl
     * 
     * @param cert cert to check
     * @param dt dat on which to check
     * @param crlUrl crl url
     * @param crlFile file to store it in
     * @return true if cert is ok
     * @throws DigiDocException
     */
    public boolean checkCertificate(X509Certificate cert, Date dt, String crlUrl, String crlFile)
                    throws DigiDocException;

}
