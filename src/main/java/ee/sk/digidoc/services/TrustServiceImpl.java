package ee.sk.digidoc.services;

import java.io.File;
import java.io.FileInputStream;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.tsl.TSPService;
import ee.sk.digidoc.tsl.TrustServiceStatusList;
import ee.sk.digidoc.tsl.TslParser;
import ee.sk.utils.DDUtils;

/**
 * SAX implementation of TrustServiceFactory
 * Provides methods for reading a DigiDoc file
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class TrustServiceImpl implements TrustService {
    
    /** log4j logger */
    private static Logger LOG = Logger.getLogger(TrustServiceImpl.class);
    
    /** TSL list */
    private List<TrustServiceStatusList> TSStatusList;
    
    private String OCSP_URL = "http://ocsp.sk.ee";
    
    private boolean useLocal = true;
    
    public void setUseLocal(boolean useLocal) {
        this.useLocal = useLocal;
    }
    
    public void setCACerts(Collection<String> certificates) {
        setPublicTSL();
        try {
            for (String certFile : certificates) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Loading CA cert from file " + certFile);
                }
                
                X509Certificate cert = DDUtils.readCertificate(certFile);
                if (cert != null) {
                    addCATspService(cert);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("CA subject: " + cert.getSubjectDN() + " issuer: "
                                        + cert.getIssuerX500Principal().getName("RFC1779"));
                    }
                }
            }
        } catch (DigiDocException e) {
            throw new RuntimeException(e);
        }
    }
    
    public void setOCSPCerts(Set<String> certs) {
        setPublicTSL();
        try {
            for (String certFile : certs) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Loading OCSP cert from file " + certFile);
                }
                X509Certificate cert = DDUtils.readCertificate(certFile);
                String cn = DDUtils.getCommonName(cert.getSubjectX500Principal().getName("RFC1779"));
                String caCn = DDUtils.getCommonName(DDUtils.convX509Name(cert.getIssuerX500Principal()));
                addOcspTspService(cert, OCSP_URL, cn, caCn);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Loaded OCSP cert with cn=" + cn);
                }
            }
        } catch (DigiDocException e) {
            throw new RuntimeException(e);
        }
    }
    
    public TrustServiceImpl(String tslFile, boolean useLocal) {
        this.useLocal = useLocal;
        if (TSStatusList == null) TSStatusList = new ArrayList<TrustServiceStatusList>();
        try {
            if (tslFile != null && tslFile.length() > 0) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Reading TSL from file: " + tslFile);
                }
                File file = new File(tslFile);
                if (file.isFile() && file.canRead()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Reading TSL: " + file.getAbsolutePath());
                    }
                    TslParser parser = new TslParser();
                    FileInputStream fis = new FileInputStream(file);
                    TrustServiceStatusList tssl = parser.readTSL(fis);
                    fis.close();
                    if (tssl != null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Got TSL: " + tssl);
                        }
                        TSStatusList.add(tssl);
                    }
                }
            }
        } catch (DigiDocException e) {
            throw new RuntimeException(e);
        } catch (Exception ex) {
            LOG.error("Error parsing XML file: " + ex);
        }
    }
    
    private void setPublicTSL() {
        if (TSStatusList == null) TSStatusList = new ArrayList<TrustServiceStatusList>();
        if (findTslByType(TrustServiceStatusList.TYPE_LOCAL) == null) {
            TrustServiceStatusList tssl = new TrustServiceStatusList();
            tssl.setType(TrustServiceStatusList.TYPE_LOCAL);
            TSStatusList.add(tssl);
        }
    }

    /**
     * Find tsl by type name
     * 
     * @param type tsl type
     * @return TrustServiceStatusList object if found or null
     */
    private TrustServiceStatusList findTslByType(String type) {
        if (TSStatusList != null) {
            for (TrustServiceStatusList tsl : TSStatusList) {
                if (tsl.getType() != null && tsl.getType().equals(type)) return tsl;
            }
        }
        return null;
    }

    /**
     * Add new CA service
     * 
     * @param cert ca cert
     * @return TSPService object
     */
    private TSPService addCATspService(X509Certificate cert) {
        TrustServiceStatusList tssl = findTslByType(TrustServiceStatusList.TYPE_LOCAL);
        TSPService tsps = new TSPService();
        tsps.setType(TSPService.TSP_TYPE_CA_QC);
        tsps.addCertificate(cert);
        tsps.setCN(DDUtils.getCommonName(cert.getSubjectDN().getName()));
        tssl.addTSPService(tsps);
        return tsps;
    }
    
    /**
     * Add new OCSP service
     * 
     * @param cert ca cert
     * @param oscpUrl OCSP responder url
     * @param cn OCSP responder id
     * @param caCn responder ca CN
     * @return TSPService object
     */
    private TSPService addOcspTspService(X509Certificate cert, String ocspUrl, String cn, String caCn) {
        TrustServiceStatusList tssl = findTslByType(TrustServiceStatusList.TYPE_LOCAL);
        TSPService tsps = new TSPService();
        tsps.setType(TSPService.TSP_TYPE_EXT_OCSP_QC);
        tsps.addCertificate(cert);
        tsps.addServiceAccessPoint(ocspUrl);
        tsps.setCN(cn);
        tsps.setCaCN(caCn);
        tssl.addTSPService(tsps);
        return tsps;
    }
    
    private X509Certificate findCaForCertInTsl(TrustServiceStatusList tsl, X509Certificate cert) {
        Principal caP = cert.getIssuerDN();
        String subDn = cert.getSubjectDN().getName();
        for (TSPService tsps : tsl.getServices()) {
            if (tsps.isCA()) {
                for (X509Certificate c : tsps.getCerts()) {
                    Principal cp = c.getSubjectDN();
                    String caDn = c.getSubjectDN().getName();
                    if (cp.equals(caP)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Found matching CA dn: " + caDn);
                        }
                        try {
                            cert.verify(c.getPublicKey());
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("CA: " + caDn + " IS issuer of: " + subDn + " serial: "
                                                + c.getSerialNumber().toString());
                            }
                            return c;
                        } catch (Exception ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("CA: " + caDn + " IS NOT issuer of: " + subDn);
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
    
    private X509Certificate findOcspInTsl(TrustServiceStatusList tsl, String cn) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Search OCSP by cn: " + cn);
        }
        for (TSPService tsps : tsl.getServices()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service: " + tsps.getCN() + " ocsp: " + tsps.isOCSP() + " CA: " + tsps.isCA());
            }
            if (tsps.isOCSP() && tsps.getCN() != null && tsps.getCN().equalsIgnoreCase(cn)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found OCSP: " + cn);
                }
                return tsps.getCertificate(0);
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Did not find ocsp for: " + cn);
        }
        return null;
    }
    
    private List<X509Certificate> findOcspsInTsl(TrustServiceStatusList tsl, String cn, String serialNr) {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Search OCSP by cn: " + cn + " and serial: " + serialNr);
        }
        for (TSPService tsps : tsl.getServices()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service: " + tsps.getCN() + " ocsp: " + tsps.isOCSP() + " CA: " + tsps.isCA());
            }
            if (tsps.isOCSP() && tsps.getCN() != null && tsps.getCN().equalsIgnoreCase(cn)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found OCSP: " + cn);
                }
                for (X509Certificate cert : tsps.getCerts()) {
                    if (serialNr != null && serialNr.equals(cert.getSerialNumber().toString())) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Found cert: " + cert.getSubjectDN().toString() + " with serial: "
                                            + cert.getSerialNumber().toString());
                        }
                        certs.add(cert);
                    }
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found " + certs.size() + " certs for " + cn);
        }
        return certs;
    }

    /**
     * Finds direct CA cert for given user cert
     * 
     * @param cert user cert
     * @param bUseLocal use also ca certs registered in local config file
     * @return CA cert or null if not found
     */
    public X509Certificate findCaForCert(X509Certificate cert) {
        if (cert != null && TSStatusList != null && !TSStatusList.isEmpty()) {
            
            String caDn = cert.getIssuerDN().getName();
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Find CA cert for issuer: " + caDn);
            }
            
            for (TrustServiceStatusList tsl : TSStatusList) {
                if ((tsl.isLocal() && useLocal) || !tsl.isLocal()) {
                    X509Certificate ca = findCaForCertInTsl(tsl, cert);
                    if (ca != null) return ca;
                }
            }
        }
        return null;
    }
    
    /**
     * Finds direct OCSP cert for given ocsp responder id
     * 
     * @param cn OCSP responder-id
     * @param bUseLocal use also ca certs registered in local config file
     * @return OCSP cert or null if not found
     */
    public X509Certificate findOcspByCN(String cn) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Search OCSP: " + cn + " use-local: " + useLocal);
        }
        // find in TSL files at first
        for (TrustServiceStatusList tsl : TSStatusList) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("TSL: is local: " + tsl.isLocal());
            }
            if ((tsl.isLocal() && useLocal) || !tsl.isLocal()) {
                X509Certificate cert = findOcspInTsl(tsl, cn);
                if (cert != null) return cert;
            }
        }
        return null;
    }
    
    /**
     * Finds OCSP url for given user cert
     * 
     * @param cert user cert
     * @param nUrl index of url if many exist
     * @param bUseLocal use also ca certs registered in local config file
     * @return CA cert or null if not found
     */
    public String findOcspUrlForCert(X509Certificate cert, int nUrl) {
        String caCn = DDUtils.getCommonName(cert.getIssuerDN().getName());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Search ocsp url for CA: " + caCn);
        }
        
        for (TrustServiceStatusList tsl : TSStatusList) {
            if ((tsl.isLocal() && useLocal) || !tsl.isLocal()) {
                for (TSPService tsps : tsl.getServices()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Checking tsp service: " + tsps.getCaCN());
                    }
                    if (tsps.isOCSP() && tsps.getCaCN() != null && tsps.getCaCN().equals(caCn)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Found OCSP: " + caCn);
                        }
                        if (tsps.getAccessPoints() != null && nUrl >= 0 && nUrl < tsps.getAccessPoints().size()) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Found ocsp URL: " + tsps.getAccessPoints().get(nUrl));
                            }
                            return tsps.getAccessPoints().get(nUrl);
                        }
                    }
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Using default URL: " + OCSP_URL);
        }
        return OCSP_URL;
    }
    
    /**
     * Finds direct OCSP cert for given ocsp responder id
     * 
     * @param cn OCSP responder-id
     * @param bUseLocal use also ca certs registered in local config file
     * @param serialNr serial number or NULL
     * @return OCSP cert or null if not found
     */
    public List<X509Certificate> findOcspsByCNAndNr(String cn, String serialNr) {
        List<X509Certificate> certs = null;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Search OCSP: " + cn + " use-local: " + useLocal + " serial: " + serialNr);
        }
        // find in TSL files at first
        if (TSStatusList != null) {
            for (TrustServiceStatusList tsl : TSStatusList) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("TSL is local: " + tsl.isLocal());
                }
                if ((tsl.isLocal() && useLocal) || !tsl.isLocal()) {
                    certs = findOcspsInTsl(tsl, cn, serialNr);
                }
            }
        }
        return certs;
    }
}
