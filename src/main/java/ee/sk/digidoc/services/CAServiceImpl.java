package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DigiDocException;

public class CAServiceImpl implements CAService {

    private static final Logger LOG = Logger.getLogger(CAServiceImpl.class);
    
    private TrustService trustService;
    
    public CAServiceImpl(TrustService trustService) {
        this.trustService = trustService;
    }

    public boolean verifyCertificate(X509Certificate cert) throws DigiDocException {
        boolean rc = false;
        try {
            X509Certificate rCert = trustService.findCaForCert(cert);
            if (rCert != null) {
                cert.verify(rCert.getPublicKey());
                rc = true;
            }
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UNKNOWN_CA_CERT);
        }

        return rc;
    }

    /**
     * Finds the CA for this certificate if the root-certs table is not empty
     * 
     * @param cert certificate to search CA for
     * @return CA certificate
     */
    public X509Certificate findCAforCertificate(X509Certificate cert) {
        X509Certificate caCert = null;

        if (cert != null && trustService != null) {

            String dn = cert.getIssuerX500Principal().getName("RFC1779");
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Find CA cert for issuer: " + dn);
            }
            
            caCert = trustService.findCaForCert(cert);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("CA: " + ((caCert == null) ? "NULL" : "OK"));
            }

        }
        
        return caCert;
    }

}
