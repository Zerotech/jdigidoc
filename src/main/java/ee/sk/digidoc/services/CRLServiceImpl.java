package ee.sk.digidoc.services;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DigiDocException;

public class CRLServiceImpl implements CRLService {

    private static final Logger LOG = Logger.getLogger(CRLServiceImpl.class);    
    /** URL timestamp to known when to get a fresh CRL (timestamp) */
    private long m_urlLastModified = 0;
    /** flag - use LDP connection or not */
    private boolean useLdap = false;
    
    /** last/fresh CRL local filename */
    private String crlFile;
    private String crlUrl;
    private String crlSearchBase;
    private String crlFilter;
    
    private String ldapDriver;
    private String ldapUrl;
    private String ldapAttr;

    
    /**
     * Checks the cert
     * 
     * @return void
     * @param cert
     *            cert to be verified
     * @param checkDate
     *            java.util.Date
     * @throws DigiDocException
     *             for all errors
     */
    public void checkCertificate(X509Certificate cert, Date checkDate) throws DigiDocException {
        if (LOG.isInfoEnabled()) {
            LOG.info("Checking cert");
        }

        if (getCRL().isRevoked(cert)) {
            throw new DigiDocException(DigiDocException.ERR_CERT_REVOKED, "Certificate has been revoked!", null);
        } else {
            if (LOG.isInfoEnabled()) {
                LOG.info("Cert OK!");
            }
        }
    }

    private X509CRL getCRL() throws DigiDocException {
        /** current/last CRL object downloaded from SK site */
        X509CRL m_crl = null;
        
        if (useLdap) {
            if (LOG.isInfoEnabled())
                LOG.info("Get CRL from LDAP");
            try {
                SearchControls constraints = new SearchControls();
                constraints.setSearchScope(SearchControls.OBJECT_SCOPE);
                Hashtable<String, String> env = new Hashtable<String, String>();
                env.put(Context.INITIAL_CONTEXT_FACTORY, ldapDriver);
                env.put(Context.PROVIDER_URL, ldapUrl);
                InitialLdapContext ctx = new InitialLdapContext(env, new Control[0]);
                NamingEnumeration<SearchResult> ne = ctx.search(crlSearchBase, crlFilter, constraints);
                if (ne.hasMore()) {
                    SearchResult sr = ne.next();
                    Attributes attrs = sr.getAttributes();
                    Attribute subatt = attrs.get(ldapAttr);
                    byte[] byteCrl = (byte[]) subatt.get();
                    ByteArrayInputStream bais = new ByteArrayInputStream(byteCrl);
                    m_crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(bais);
                }
            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL);
            }
        } else {
            if (LOG.isInfoEnabled()) {
                LOG.info("Get CRL from HTTP");
            }

            BufferedInputStream bis = null;
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(crlUrl).openConnection();
                conn.setDoInput(true);
                long lastmodif = conn.getLastModified();
                // System.out.println("URL time: " + lastmodif + " cache time: "
                // + m_urlLastModified);
                if (m_urlLastModified == 0 || lastmodif >= m_urlLastModified) {
                    InputStream is = conn.getInputStream();
                    bis = new BufferedInputStream(is);
                    m_crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(bis);
                    m_urlLastModified = lastmodif;

                    if (LOG.isInfoEnabled()) {
                        LOG.info("Got CRL -> save");
                    }

                    saveCRL(m_crl);
                }

            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL);
            } finally {
                try {
                    if (bis != null) {
                        bis.close();
                    }
                } catch (IOException e) {
                }
            }
        }
        return m_crl;
    }

    private void saveCRL(X509CRL crl) throws DigiDocException {
        try {
            if (LOG.isInfoEnabled()) {
                LOG.info("Writing CRL to: " + crlFile);
            }

            File f = new File(crlFile);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(crl.getEncoded());
            fos.close();

            if (LOG.isInfoEnabled()) {
                LOG.info("CRL file saved!");
            }

        } catch (Exception ex) {
            LOG.error("Error writing CRL to file: " + crlFile);
            DigiDocException.handleException(ex, DigiDocException.ERR_SAVE_CRL);
        }
    }

    public void setLdapDriver(String ldapDriver) {
        this.ldapDriver = ldapDriver;
    }
    
    public void setLdapUrl(String ldapUrl) {
        this.ldapUrl = ldapUrl;
    }
    
    public void setLdapAttr(String ldapAttr) {
        this.ldapAttr = ldapAttr;
    }
    
    public void setUseLdap(boolean useLdap) {
        this.useLdap = useLdap;
    }

    public void setCrlUrl(String crlUrl) {
        this.crlUrl = crlUrl;
    }
    
    public void setCrlFile(String crlFile) {
        this.crlFile = crlFile;
    }
    
    public void setCrlFilter(String crlFilter) {
        this.crlFilter = crlFilter;
    }
    
    public void setCrlSearchBase(String crlSearchBase) {
        this.crlSearchBase = crlSearchBase;
    }
    
}
