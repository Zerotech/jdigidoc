package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

public class CAServiceImpl implements CAService {

    private static final Logger LOG = Logger.getLogger(CAServiceImpl.class);

    private Hashtable<String, X509Certificate> m_rootCerts = new Hashtable<String, X509Certificate>();

    public void setCACerts(Collection<String> certificates) {
        try {
            for (String certFile : certificates) {
                LOG.debug("Loading CA cert from file " + certFile);

                X509Certificate cert = SignedDoc.readCertificate(certFile);

                if (cert != null) {
                    if (LOG.isDebugEnabled())
                        LOG.debug("CA subject: " + cert.getSubjectDN() + " issuer: "
                                + cert.getIssuerX500Principal().getName("RFC1779"));
                    m_rootCerts.put(cert.getSubjectX500Principal().getName("RFC1779"), cert);
                }
            }
        } catch (DigiDocException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verifyCertificate(X509Certificate cert) throws DigiDocException {
        boolean rc = false;
        try {
            X509Certificate rCert = (X509Certificate) m_rootCerts.get(cert.getIssuerX500Principal().getName("RFC1779"));
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
     * @param cert
     *            certificate to search CA for
     * @return CA certificate
     */
    public X509Certificate findCAforCertificate(X509Certificate cert) {
        X509Certificate caCert = null;
        if (cert != null && m_rootCerts != null && !m_rootCerts.isEmpty()) {
            // String cn =
            // SignedDoc.getCommonName(cert.getIssuerX500Principal().getName("RFC1779"));
            String dn = cert.getIssuerX500Principal().getName("RFC1779");
            if (LOG.isDebugEnabled())
                LOG.debug("Find CA cert for issuer: " + dn);
            caCert = (X509Certificate) m_rootCerts.get(dn);
            if (LOG.isDebugEnabled())
                LOG.debug("CA: " + ((caCert == null) ? "NULL" : "OK"));
        }
        return caCert;
    }

}
