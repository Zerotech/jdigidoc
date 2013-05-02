package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TrustService {
    
    /**
     * Finds direct CA cert for given user cert
     * 
     * @param cert user cert
     * @param bUseLocal use also ca certs registered in local config file
     * @return CA cert or null if not found
     */
    public X509Certificate findCaForCert(X509Certificate cert);
    
    /**
     * Finds direct OCSP cert for given ocsp responder id
     * 
     * @param cn OCSP responder-id
     * @param bUseLocal use also ca certs registered in local config file
     * @return OCSP cert or null if not found
     */
    public X509Certificate findOcspByCN(String cn);
    
    /**
     * Finds OCSP url for given user cert
     * 
     * @param cert user cert
     * @param nUrl index of url if many exist
     * @param bUseLocal use also ca certs registered in local config file
     * @return CA cert or null if not found
     */
    public String findOcspUrlForCert(X509Certificate cert, int nUrl);
    
    /**
     * Finds direct OCSP cert for given ocsp responder id
     * 
     * @param cn OCSP responder-id
     * @param bUseLocal use also ca certs registered in local config file
     * @param serialNr serial number or NULL
     * @return OCSP cert or null if not found
     */
    public List<X509Certificate> findOcspsByCNAndNr(String cn, String serialNr);

}
