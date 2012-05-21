package ee.sk.digidoc.services;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Notary;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.utils.Base64Util;
import ee.sk.utils.DDUtils;

public class BouncyCastleNotaryServiceImpl implements NotaryService {

    private static final String nonceOid = "1.3.6.1.5.5.7.48.1.2";
    private static final String sha1NoSign = "1.3.14.3.2.26";
    private static final String subjectKeyIdentifier = "2.5.29.14"; 
    private static final Logger LOG = Logger.getLogger(BouncyCastleNotaryServiceImpl.class);
    
    private boolean signRequests;
    private X509Certificate signRequestCert;
    private PrivateKey signRequestKey;
    
    private Hashtable<String, X509Certificate> ocspCerts = new Hashtable<String, X509Certificate>();

    private boolean useOCSP = true;
    
    private String responderUrl;

    private final CRLService crlService;
    private final CAService caService;
    
    public void setUseOCSP(boolean useOCSP) {
        this.useOCSP = useOCSP;
    }
    
    public void setResponderUrl(String responderUrl) {
        this.responderUrl = responderUrl;
    }
    
    public void setSignRequests(boolean signRequests) {
        this.signRequests = signRequests;
    }
    
    /**
     * Returns the n-th OCSP responders certificate if there are many
     * certificates registered for this responder.
     * TODO idx partially remains, adding of idx-ed keys was removed.
     * 
     * @param responderCN
     *            responder-id's CN
     * @param idx
     *            certificate index starting with 0
     * @returns OCSP responders certificate or null if not found
     */
    public X509Certificate findNotaryCertByIndex(String responderCN, int idx) {
        X509Certificate cert = null;

        if (LOG.isInfoEnabled()) {
            LOG.info("Find responder for: " + responderCN + " index: " + idx);
        }
            
        String certKey = null;
        if (idx == 0) {
            certKey = responderCN;
        } else {
            certKey = responderCN + "-" + idx;
        }
            
        if (LOG.isInfoEnabled()) {
            LOG.info("Searching responder: " + certKey);
        }
            
        cert = ocspCerts.get(certKey);
        
        if (LOG.isInfoEnabled() && cert != null && certKey != null) {
            LOG.info("Selecting cert " + cert.getSerialNumber().toString() 
                    + " key: " + certKey 
                    + " valid until: " + cert.getNotAfter().toString());
        }

        return cert;
    }

    /**
     * Returns the OCSP responders certificate
     * 
     * @param responderCN
     *            responder-id's CN
     * @param specificCertNr
     *            specific cert number that we search. If this parameter is null
     *            then the newest cert is seleced (if many exist)
     * @returns OCSP responders certificate
     */
    public X509Certificate getNotaryCert(String responderCN, String specificCertNr) {
        X509Certificate cert1 = null, cert2 = null;
        Date d1 = null;
        String key = null;

        if (LOG.isInfoEnabled()) {
            LOG.info("Find responder for: " + responderCN + " cert: " + ((specificCertNr != null) ? specificCertNr : "NEWEST"));
        }
            
        int i = 0;
        do {
            cert2 = null;
            String certKey = null;
            if (i == 0) {
                certKey = responderCN;
            } else {
                certKey = responderCN + "-" + i;
            }
                
            if (LOG.isInfoEnabled()) {
                LOG.info("Searching responder: " + certKey);
            }

            cert2 = (X509Certificate) ocspCerts.get(certKey);
            if (cert2 != null) {
                if (specificCertNr != null) { // specific cert
                    String certNr = cert2.getSerialNumber().toString();
                    if (certNr.equals(specificCertNr)) {
                        if (LOG.isInfoEnabled()) {
                            LOG.info("Found specific responder: " + specificCertNr);
                        }

                        return cert2;
                    }
                } else { // just the freshest
                    Date d2 = cert2.getNotAfter();
                    if (cert1 == null || d1 == null || d1.before(d2)) {
                        d1 = d2;
                        key = certKey;
                        cert1 = cert2;
                        
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Newer cert valid until: " + d2);
                        }
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Responder: " + certKey + " not found! ");
                }
            }
            i++;
        } while (cert2 != null || i < 2);
        
        if (LOG.isInfoEnabled() && cert1 != null && key != null) {
            LOG.info("Selecting cert " + cert1.getSerialNumber().toString() + " key: " + key + " valid until: "
                    + cert1.getNotAfter().toString());
        }
            
        return cert1;
    }

    // VS: 02.01.2009 - fix finding ocsp responders cert
    /**
     * Finds notary cert by certificates public key hash
     * 
     * @param certHash
     *            cert hast to search for
     * @return certificate if fond or null if not
     */
    public X509Certificate findNotaryCertByKeyHash(byte[] certHash) {
        if (LOG.isInfoEnabled()) {
            LOG.info("find notary cert by hash: " + Base64Util.encode(certHash));
        }

        Enumeration<X509Certificate> eCerts = ocspCerts.elements();
        while (eCerts.hasMoreElements()) {
            X509Certificate cert = eCerts.nextElement();
            byte[] hash = getCertFingerprint(cert);
            
            if (LOG.isInfoEnabled()) {
                LOG.info("Cert: " + cert.getSubjectDN().getName() 
                        + " fingerprint: " + Base64Util.encode(hash)
                        + " len: " + hash.length 
                        + " compare: " + Base64Util.encode(certHash));
            }
                
            if (DDUtils.compareDigests(hash, certHash)) {
                return cert;
            }
        }
        
        return null; // not found
    }

    /**
     * return certificate's fingerprint
     * 
     * @param cert
     *            X509Certificate object
     * @return certificate's fingerprint or null
     */
    public static byte[] getCertFingerprint(X509Certificate cert) {
        byte[] bdat = cert.getExtensionValue("2.5.29.14");
        if (bdat != null) {
            if (bdat.length > 20) {
                byte[] bdat2 = new byte[20];
                System.arraycopy(bdat, bdat.length - 20, bdat2, 0, 20);
                return bdat2;
            } else
                return bdat;
        }

        return null;
    }

    /**
     * Get confirmation from AS Sertifitseerimiskeskus by creating an OCSP
     * request and parsing the returned OCSP response
     * 
     * @param nonce
     *            signature nonce
     * @param signersCert
     *            signature owners cert
     * @param caCert
     *            CA cert for this signer
     * @param notaryCert
     *            notarys own cert
     * @param notId
     *            new id for Notary object
     * @returns Notary object
     */
    public Notary getConfirmation(byte[] nonce, X509Certificate signersCert, X509Certificate caCert,
            X509Certificate notaryCert, String notId) // TODO: remove param
                                                      // notaryCert
            throws DigiDocException {
        Notary not = null;
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("getConfirmation, nonce " + Base64Util.encode(nonce, 0) + " cert: "
                        + ((signersCert != null) ? signersCert.getSerialNumber().toString() : "NULL") + " CA: "
                        + ((caCert != null) ? caCert.getSerialNumber().toString() : "NULL") + " responder: "
                        + ((notaryCert != null) ? notaryCert.getSerialNumber().toString() : "NULL") + " notId: "
                        + notId + " signRequest: " + signRequests);
                LOG.debug("Check cert: " + ((signersCert != null) ? signersCert.getSubjectDN().getName() : "NULL"));
                LOG.debug("Check CA cert: " + ((caCert != null) ? caCert.getSubjectDN().getName() : "NULL"));
            }
            
            // create the request - sign the request if necessary
            OCSPReq req = createOCSPRequest(nonce, signersCert, caCert, signRequests);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }
                
            // send it
            OCSPResp resp = sendRequest(req);
            // debugWriteFile("resp.der", resp.getEncoded());
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }
            
            // check response status
            verifyRespStatus(resp);
            // check the result
            not = parseAndVerifyResponse(null, notId, signersCert, resp, nonce);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Confirmation OK!");
            }
                
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return not;
    }

    /**
     * Get confirmation from AS Sertifitseerimiskeskus by creating an OCSP
     * request and parsing the returned OCSP response
     * 
     * @param sig
     *            Signature object.
     * @param signersCert
     *            signature owners cert
     * @param caCert
     *            CA cert for this signer
     * @returns Notary object
     */
    public Notary getConfirmation(Signature sig, X509Certificate signersCert, X509Certificate caCert)
            throws DigiDocException {

        Notary not = null;
        try {
            String notId = sig.getId().replace('S', 'N');
            // calculate the nonce
            byte[] nonce = DDUtils.digest(sig.getSignatureValue().getValue());
            X509Certificate notaryCert = null;
            if (sig.getUnsignedProperties() != null)
                notaryCert = sig.getUnsignedProperties().getRespondersCertificate();
            // check the result
            not = getConfirmation(nonce, signersCert, caCert, notaryCert, notId);
            // add cert to signature
            if (notaryCert == null && sig != null && sig.getUnsignedProperties() != null) {
                OCSPResp resp = new OCSPResp(sig.getUnsignedProperties().getNotary().getOcspResponseData());
                if (resp != null && resp.getResponseObject() != null) {
                    // VS: 02.01.2009 - fix finding ocsp responders cert
                    notaryCert = findNotaryCertByResponderId((BasicOCSPResp) resp.getResponseObject());
                    if (LOG.isDebugEnabled())
                        LOG.debug("Using notary cert: "
                                + ((notaryCert != null) ? notaryCert.getSubjectDN().getName() : "NULL"));
                    if (notaryCert == null)
                        throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP responders cert not found",
                                null);
                    // VS: 02.01.2009 - fix finding ocsp responders cert
                    sig.getUnsignedProperties().setRespondersCertificate(notaryCert);
                }
            }
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return not;
    }

    /*
     * private String ocspFileName(X509Certificate cert) { StringBuffer sb = new
     * StringBuffer(cert.getSerialNumber().toString()); sb.append("_"); Date
     * dtNow = new Date(); SimpleDateFormat df = new SimpleDateFormat("HHmmss");
     * sb.append(df.format(dtNow)); return sb.toString(); }
     */

    /**
     * Verifies the certificate by creating an OCSP request and sending it to SK
     * server.
     * 
     * @param cert
     *            certificate to verify
     * @throws DigiDocException
     *             if the certificate is not valid
     */
    public void checkCertificate(X509Certificate cert) throws DigiDocException {
        try {
            if (useOCSP) {
                // create the request
                X509Certificate caCert = caService.findCAforCertificate(cert);
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Find CA for: " + DDUtils.getCommonName(cert.getIssuerX500Principal().getName("RFC1779")));
                    LOG.debug("Check cert: " + cert.getSubjectDN().getName());
                    LOG.debug("Check CA cert: " + caCert.getSubjectDN().getName());
                }
                
                String strTime = new java.util.Date().toString();
                byte[] nonce1 = DDUtils.digest(strTime.getBytes());
                
                OCSPReq req = createOCSPRequest(nonce1, cert, caCert, signRequests);
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Sending ocsp request: " + req.getEncoded().length + " bytes");
                    LOG.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
                }
                
                // send it
                OCSPResp resp = sendRequest(req);
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got ocsp response: " + resp.getEncoded().length + " bytes");
                    LOG.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
                }
                
                // check response status
                verifyRespStatus(resp);
                // now read the info from the response
                BasicOCSPResp basResp = (BasicOCSPResp) resp.getResponseObject();
                
                byte[] nonce2 = getNonce(basResp);
                if (!DDUtils.compareDigests(nonce1, nonce2)) {
                    throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                            "Invalid nonce value! Possible replay attack!", null);
                }

                // verify the response
                try {
                    // VS: 02.01.2009 - fix finding ocsp responders cert
                    X509Certificate notaryCert = findNotaryCertByResponderId(basResp);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using notary cert: " + ((notaryCert != null) ? notaryCert.getSubjectDN().getName() : "NULL"));
                    }

                    if (notaryCert == null) {
                        throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP responders cert not found", null);
                    }

                    basResp.verify(notaryCert.getPublicKey(), "BC");
                        
                    // VS: 02.01.2009 - fix finding ocsp responders cert
                } catch (Exception ex) {
                    LOG.error("OCSP Signature verification error!!!", ex);
                    DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
                }
                
                // check the response about this certificate
                checkCertStatus(cert, basResp);
            } else {
                crlService.checkCertificate(cert, new Date());
            }
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
    }

    /**
     * Check the response and parse it's data
     * 
     * @param sig
     *            Signature object
     * @param notId
     *            new id for Notary object
     * @param signersCert
     *            signature owners certificate
     * @param resp
     *            OCSP response
     * @param nonce1
     *            nonve value used for request
     * @returns Notary object
     */
    private Notary parseAndVerifyResponse(Signature sig, String notId, X509Certificate signersCert, OCSPResp resp,
            byte[] nonce1) throws DigiDocException {
        Notary not = null;
        X509Certificate notaryCert = null;

        // check the result
        if (resp == null || resp.getStatus() != OCSPRespStatus.SUCCESSFUL) {
            throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL, "OCSP response unsuccessfull!", null);
        }
        
        try {
            // now read the info from the response
            BasicOCSPResp basResp = (BasicOCSPResp) resp.getResponseObject();
            // find real notary cert suitable for this response
            int nNotIdx = 0;
            String respondIDstr = responderIDtoString(basResp);
            String notIdCN = DDUtils.getCommonName(respondIDstr);
            Exception exVerify = null;
            boolean bOk = false;
            do {
                exVerify = null;
                if (LOG.isInfoEnabled()) {
                    LOG.info("Find notary cert for: " + notIdCN + " index: " + nNotIdx);
                }
                    
                notaryCert = findNotaryCertByIndex(notIdCN, nNotIdx);
                if (notaryCert != null) {
                    try {
                        bOk = basResp.verify(notaryCert.getPublicKey(), "BC");
                        if (LOG.isInfoEnabled()) {
                            LOG.info("Verification with cert: " + notaryCert.getSerialNumber().toString()
                                    + " idx: " + nNotIdx + " RC: " + bOk);
                        }
                    } catch (Exception ex) {
                        exVerify = ex;
                        if (LOG.isInfoEnabled()) {
                            LOG.info("Notary cert index: " + nNotIdx + " is not usable for this response!");
                        }
                            
                    }
                }
                nNotIdx++;
            } while (notaryCert != null && (exVerify != null || !bOk));
            
            // if no suitable found the report error
            if (exVerify != null) {
                LOG.error("OCSP verification error!!!", exVerify);
                DigiDocException.handleException(exVerify, DigiDocException.ERR_OCSP_VERIFY);
            }
            
            if (LOG.isInfoEnabled() && notaryCert != null) {
                LOG.info("Using responder cert: " + notaryCert.getSerialNumber().toString());
            }

            // done't care about SingleResponses because we have
            // only one response and the whole response was successful
            // but we should verify that the nonce hasn't changed
            byte[] nonce2 = getNonce(basResp);
            boolean ok = true;
            
            if (nonce1.length != nonce2.length) {
                ok = false;
            }
            
            for (int i = 0; i < nonce1.length; i++) {
                if (nonce1[i] != nonce2[i]) {
                    ok = false;
                }
            }

            if (!ok && sig != null && !sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_4)) {
                LOG.error("DDOC ver: " + sig.getSignedDoc().getVersion() 
                        + " SIG: " + sig.getId()
                        + " Real nonce: " + Base64Util.encode(nonce2, 0) 
                        + " My nonce: " + Base64Util.encode(nonce1, 0));
                throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                        "OCSP response's nonce doesn't match the requests nonce!", null);
            }
            
            // check the response on our cert
            checkCertStatus(signersCert, basResp);
            // create notary
            not = new Notary(notId, resp.getEncoded(), respondIDstr, basResp.getProducedAt());
            
            if (notaryCert != null) {
                not.setCertNr(notaryCert.getSerialNumber().toString());
            }
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_PARSE);
        }
        return not;
    }

    /**
     * Verifies that the OCSP response is about our signers cert and the
     * response status is successful
     * 
     * @param sig
     *            Signature object
     * @param basResp
     *            OCSP Basic response
     * @throws DigiDocException
     *             if the response is not successful
     */
    private void checkCertStatus(Signature sig, BasicOCSPResp basResp) throws DigiDocException {
        checkCertStatus(sig.getKeyInfo().getSignersCertificate(), basResp);
    }

    /**
     * Verifies that the OCSP response is about our signers cert and the
     * response status is successful
     * 
     * @param sig
     *            Signature object
     * @param basResp
     *            OCSP Basic response
     * @throws DigiDocException
     *             if the response is not successful
     */
    private void checkCertStatus(X509Certificate cert, BasicOCSPResp basResp) throws DigiDocException {
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Checking response status, CERT: " + cert.getSubjectDN().getName() 
                        + " SEARCH: " + DDUtils.getCommonName(cert.getIssuerX500Principal().getName("RFC1779")));
            }
                
            // check the response on our cert
            X509Certificate caCert = caService.findCAforCertificate(cert);

            if (LOG.isDebugEnabled()) {
                LOG.debug("CA cert: " + ((caCert == null) ? "NULL" : "OK"));
                LOG.debug("RESP: " + basResp);
                LOG.debug("CERT: " + cert.getSubjectDN().getName() + " ISSUER: "
                        + cert.getIssuerX500Principal().getName("RFC1779"));
                
                if (caCert != null) {
                    LOG.debug("CA CERT: " + caCert.getSubjectDN().getName());
                }
            }
            
            SingleResp[] sresp = basResp.getResponses();
            CertificateID rc = creatCertReq(cert, caCert);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Search alg: " + rc.getHashAlgOID() 
                        + " serial: " + rc.getSerialNumber() 
                        + " issuer: " + Base64Util.encode(rc.getIssuerKeyHash()) 
                        + " subject: " + Base64Util.encode(rc.getIssuerNameHash()));
            }
                
            boolean ok = false;
            for (int i = 0; i < sresp.length; i++) {
                CertificateID id = sresp[i].getCertID();
                if (id != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Got alg: " + id.getHashAlgOID() 
                                + " serial: " + id.getSerialNumber()
                                + " issuer: " + Base64Util.encode(id.getIssuerKeyHash()) 
                                + " subject: " + Base64Util.encode(id.getIssuerNameHash()));
                    }

                    if (rc.getHashAlgOID().equals(id.getHashAlgOID())
                            && rc.getSerialNumber().equals(id.getSerialNumber())
                            && DDUtils.compareDigests(rc.getIssuerKeyHash(), id.getIssuerKeyHash())
                            && DDUtils.compareDigests(rc.getIssuerNameHash(), id.getIssuerNameHash())) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Found it!");
                        }
                            
                        ok = true;
                        Object status = sresp[i].getCertStatus();
                        if (status != null) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("CertStatus: " + status.getClass().getName());
                            }
                                
                            if (status instanceof RevokedStatus) {
                                LOG.error("Certificate has been revoked!");
                                throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                                        "Certificate has been revoked!", null);
                            }
                            
                            if (status instanceof UnknownStatus) {
                                LOG.error("Certificate status is unknown!");
                                throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                                        "Certificate status is unknown!", null);
                            }

                        }
                        break;
                    }
                }
            }

            if (!ok) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Error checkCertStatus - not found ");
                }

                throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS, "Bad OCSP response status!", null);
            }
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            LOG.error("Error checkCertStatus: " + ex);
            throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS, "Error checking OCSP response status!",
                    null);
        }
    }

    /**
     * Check the response and parse it's data Used by
     * UnsignedProperties.verify()
     * 
     * @param not
     *            initial Notary object that contains only the raw bytes of an
     *            OCSP response
     * @returns Notary object with data parsed from OCSP response
     */
    public Notary parseAndVerifyResponse(Signature sig, Notary not) throws DigiDocException {
        try {
            OCSPResp resp = new OCSPResp(not.getOcspResponseData());
            // now read the info from the response
            BasicOCSPResp basResp = (BasicOCSPResp) resp.getResponseObject();
            // verify the response
            try {
                // X509Certificate notaryCert =
                // sig.getUnsignedProperties().getRespondersCertificate();
                String respondIDstr = responderIDtoString(basResp);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SIG: " + ((sig == null) ? "NULL" : sig.getId()));
                    LOG.debug("UP: "
                            + ((sig.getUnsignedProperties() == null) ? "NULL" : "OK: "
                                    + sig.getUnsignedProperties().getNotary().getId()));
                    LOG.debug("RESP-CERT: "
                            + ((sig.getUnsignedProperties().getRespondersCertificate() == null) ? "NULL" : "OK"));
                    X509Certificate notCer = sig.getUnsignedProperties().getRespondersCertificate();
                    if (notCer != null)
                        LOG.debug("NotCer: " + notCer.getSerialNumber() + " - " + notCer.getSubjectDN().getName());
                    ee.sk.digidoc.CertID cid = sig.getCertID(ee.sk.digidoc.CertID.CERTID_TYPE_RESPONDER);
                    if (cid != null)
                        LOG.debug("CID: " + cid.getType() + " id: " + cid.getId() + ", " + cid.getSerial()
                                + " issuer: " + cid.getIssuer());
                }
                String ddocRespCertNr = sig.getUnsignedProperties().getRespondersCertificate().getSerialNumber()
                        .toString();
                X509Certificate notaryCert = getNotaryCert(DDUtils.getCommonName(respondIDstr), ddocRespCertNr);
                if (notaryCert == null)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_RECPONDER_NOT_TRUSTED,
                            "No certificate for responder: \'" + respondIDstr + "\' found in local certificate store!",
                            null);
                if (LOG.isDebugEnabled())
                    LOG.debug("Verify using responders cert: " + ((notaryCert != null) ? "OK" : "NULL"));
                // X509Certificate notaryCert =
                // getNotaryCert(SignedDoc.getCommonName(respondIDstr));
                basResp.verify(notaryCert.getPublicKey(), "BC");

            } catch (Exception ex) {
                LOG.error("Signature verification error: " + ex);
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            // done't care about SingleResponses because we have
            // only one response and the whole response was successfull
            // but we should verify that the nonce hasn't changed
            // calculate the nonce
            byte[] nonce1 = DDUtils.digest(sig.getSignatureValue().getValue());
            byte[] nonce2 = getNonce(basResp);
            boolean ok = true;
            if (nonce1.length != nonce2.length)
                ok = false;
            for (int i = 0; i < nonce1.length; i++)
                if (nonce1[i] != nonce2[i])
                    ok = false;
            // TODO: investigate further
            /*
             * if(!ok && sig.getSignedDoc() != null &&
             * !sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_4)) {
             * if(m_logger.isDebugEnabled()) m_logger.debug("SigVal\n---\n" +
             * Base64Util.encode(sig.getSignatureValue().getValue()) +
             * "\n---\nOCSP\n---\n" +
             * Base64Util.encode(not.getOcspResponseData()) + "\n---\n");
             * m_logger.error("DDOC ver: " + sig.getSignedDoc().getVersion() +
             * " SIG: " + sig.getId() + " NOT: " + not.getId() + " Real nonce: "
             * + Base64Util.encode(nonce2, 0) + " My nonce: " +
             * Base64Util.encode(nonce1, 0)); m_logger.error("SIG:\n---\n" +
             * sig.toString() + "\n--\n"); throw new
             * DigiDocException(DigiDocException.ERR_OCSP_NONCE,
             * "OCSP response's nonce doesn't match the requests nonce!", null);
             * }
             */
            // check the response on our cert
            checkCertStatus(sig, basResp);
            not.setProducedAt(basResp.getProducedAt());
            not.setResponderId(responderIDtoString(basResp));
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_PARSE);
        }
        return not;
    }

    // VS: 02.01.2009 - fix finding ocsp responders cert
    /**
     * Finds notary cert by responder-id field in basic ocsp response
     * 
     * @param basResp
     *            basic ocsp response
     * @return notary cert or null if not found
     */
    private X509Certificate findNotaryCertByResponderId(BasicOCSPResp basResp) {
        if (basResp != null) {
            ResponderID respid = basResp.getResponderId().toASN1Object();
            Object o = ((DERTaggedObject) respid.toASN1Object()).getObject();

            if (o instanceof ASN1Sequence) {
                X509Name name = new X509Name((ASN1Sequence) o);
                String dn = name.toString();
                String cn = DDUtils.getCommonName(dn);
                return getNotaryCert(cn, null);
                
            } else if (o instanceof DEROctetString) {
                DEROctetString dHash = (DEROctetString) o;
                byte[] cHash = null;
                byte[] cHash2 = null;
                byte[] cHash3 = null;
                try {
                    cHash = dHash.getOctets();
                    cHash2 = dHash.getDEREncoded();
                    cHash3 = dHash.getEncoded();
                } catch (Exception ex) {
                    LOG.error("Error: " + ex);
                }
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Find notary for octects: " + Base64Util.encode(cHash) 
                            + " len: " + cHash.length
                            + " hex: " + bin2hex(cHash) 
                            + " der: " + Base64Util.encode(cHash2) 
                            + " len: " + cHash2.length 
                            + " enc: " + Base64Util.encode(cHash3) 
                            + " len: " + cHash3.length);
                }

                return findNotaryCertByKeyHash(cHash);
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    // VS: 02.01.2009 - fix finding ocsp responders cert

    /**
     * Get String represetation of ResponderID
     * 
     * @param basResp
     * @return stringified responder ID
     */
    private String responderIDtoString(BasicOCSPResp basResp) {
        if (basResp != null) {
            ResponderID respid = basResp.getResponderId().toASN1Object();
            Object o = ((DERTaggedObject) respid.toASN1Object()).getObject();

            if (o instanceof ASN1Sequence) {
                X509Name name = new X509Name((ASN1Sequence) o);
                return "byName: " + name.toString();
            } else if (o instanceof DEROctetString) {
                // TODO: fix ...
                return "byKey: " + o.toString();
            } else {
                return null;
            }
        } else
            return null;
    }

    /**
     * Method to get NONCE array from responce
     * 
     * @param basResp
     * @return OCSP nonce value
     */
    private byte[] getNonce(BasicOCSPResp basResp) {
        if (basResp != null) {
            X509Extensions ext = basResp.getResponseExtensions();
            X509Extension ex1 = ext.getExtension(new DERObjectIdentifier(nonceOid));
            byte[] nonce2 = ex1.getValue().getOctets();

            return nonce2;
        } else
            return null;
    }

    /**
     * Helper method to verify response status
     * 
     * @param resp
     *            OCSP response
     * @throws DigiDocException
     *             if the response status is not ok
     */
    private void verifyRespStatus(OCSPResp resp) throws DigiDocException {
        int status = resp.getStatus();
        
        switch (status) {
        case OCSPRespStatus.INTERNAL_ERROR:
            LOG.error("An internal error occured in the OCSP Server!");
            break;
        case OCSPRespStatus.MALFORMED_REQUEST:
            LOG.error("Your request did not fit the RFC 2560 syntax!");
            break;
        case OCSPRespStatus.SIGREQUIRED:
            LOG.error("Your request was not signed!");
            break;
        case OCSPRespStatus.TRY_LATER:
            LOG.error("The server was too busy to answer you!");
            break;
        case OCSPRespStatus.UNAUTHORIZED:
            LOG.error("The server could not authenticate you!");
            break;
        case OCSPRespStatus.SUCCESSFUL:
            break;
        default:
            LOG.error("Unknown OCSPResponse status code! " + status);
        }
        
        if (resp == null || resp.getStatus() != OCSPRespStatus.SUCCESSFUL) {
            throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL, "OCSP response unsuccessfull! ", null);
        }
            
    }

    /**
     * Method for creating CertificateID for OCSP request
     * 
     * @param signersCert
     * @param caCert
     * @param provider
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws CertificateEncodingException
     */
    private CertificateID creatCertReq(X509Certificate signersCert, X509Certificate caCert)
            throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, DigiDocException {
        MessageDigest digest = MessageDigest.getInstance(sha1NoSign, "BC");
        
        if (LOG.isTraceEnabled()) {
            LOG.trace("CA cert: " + ((caCert != null) ? caCert.toString() : "NULL"));
        }

        X509Principal issuerName = PrincipalUtil.getSubjectX509Principal(caCert);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("CA issuer: " + ((issuerName != null) ? issuerName.getName() : "NULL"));
        }
            
        // Issuer name hash
        digest.update(issuerName.getEncoded());
        ASN1OctetString issuerNameHash = new BERConstructedOctetString(digest.digest());

        // Issuer key hash will be readed out from X509extendions
        // 4 first bytes are not useful for me, oid 2.5.29.15 contains keyid
        byte[] arr = caCert.getExtensionValue(subjectKeyIdentifier);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuer key hash: " + ((arr != null) ? arr.length : 0));
        }
        
        if (arr == null || arr.length == 0) {
            throw new DigiDocException(DigiDocException.ERR_CA_CERT_READ,
                    "CA certificate has no SubjectKeyIdentifier extension!", null);
        }
            
        byte[] arr2 = new byte[arr.length - 4];
        System.arraycopy(arr, 4, arr2, 0, arr2.length);
        ASN1OctetString issuerKeyHash = new BERConstructedOctetString(arr2);

        CertID cerid = new CertID(new AlgorithmIdentifier(sha1NoSign), issuerNameHash, issuerKeyHash,
                new DERInteger(signersCert.getSerialNumber()));
        return new CertificateID(cerid);
    }

    /**
     * Creates a new OCSP request
     * 
     * @param nonce
     *            128 byte RSA+SHA1 signatures digest Use null if you want to
     *            verify only the certificate and this is not related to any
     *            signature
     * @param signersCert
     *            signature owners cert
     * @param caCert
     *            CA cert for this signer
     * @param bSigned
     *            flag signed request or not
     */
    private OCSPReq createOCSPRequest(byte[] nonce, X509Certificate signersCert, X509Certificate caCert, boolean bSigned)
            throws DigiDocException {
        OCSPReq req = null;
        OCSPReqGenerator ocspRequest = new OCSPReqGenerator();
        try {
            // Create certificate id, for OCSP request
            CertificateID certId = creatCertReq(signersCert, caCert);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Request for: " + certId.getHashAlgOID() 
                        + " serial: " + certId.getSerialNumber()
                        + " issuer: " + Base64Util.encode(certId.getIssuerKeyHash()) 
                        + " subject: " + Base64Util.encode(certId.getIssuerNameHash()));
            }

            ocspRequest.addRequest(certId);

            if (nonce != null) {
                ASN1OctetString ocset = new BERConstructedOctetString(nonce);
                X509Extension ext = new X509Extension(false, ocset);
                // nonce Identifier
                DERObjectIdentifier nonceIdf = new DERObjectIdentifier(nonceOid);
                Hashtable<DERObjectIdentifier, X509Extension> tbl = new Hashtable<DERObjectIdentifier, X509Extension>(1);
                tbl.put(nonceIdf, ext);
                // create extendions, with one extendion(NONCE)
                X509Extensions extensions = new X509Extensions(tbl);
                ocspRequest.setRequestExtensions(extensions);
            }

            GeneralName name = null;
            if (bSigned) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SignCert: " + ((signRequestCert != null) ? signRequestCert.toString() : "NULL"));
                }

                name = new GeneralName(PrincipalUtil.getSubjectX509Principal(signRequestCert));
            } else {
                name = new GeneralName(PrincipalUtil.getSubjectX509Principal(signersCert));
            }

            ocspRequest.setRequestorName(name);

            if (bSigned) {
                // lets generate signed request
                X509Certificate[] chain = { signRequestCert };
                req = ocspRequest.generate("SHA1WITHRSA", signRequestKey, chain, "BC");
                if (!req.verify(signRequestCert.getPublicKey(), "BC")) {
                    LOG.error("Verify failed");
                }
            } else { // unsigned request
                req = ocspRequest.generate();
            }

        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_REQ_CREATE);
        }
        return req;
    }

    /**
     * Sends the OCSP request to Notary and retrieves the response
     * 
     * @param req
     *            OCSP request
     * @returns OCSP response
     */
    private OCSPResp sendRequest(OCSPReq req) throws DigiDocException {
        OCSPResp resp = null;

        try {
            byte[] breq = req.getEncoded();
            URL url = new URL(responderUrl);
            URLConnection con = url.openConnection();
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            OutputStream os = con.getOutputStream();
            os.write(breq);
            os.close();
            // read the response
            InputStream is = con.getInputStream();
            int cl = con.getContentLength();
            byte[] bresp = null;

            if (cl > 0) {
                int avail = 0;
                do {
                    avail = is.available();
                    byte[] data = new byte[avail];
                    int rc = is.read(data);
                    if (bresp == null) {
                        bresp = new byte[rc];
                        System.arraycopy(data, 0, bresp, 0, rc);
                    } else {
                        byte[] tmp = new byte[bresp.length + rc];
                        System.arraycopy(bresp, 0, tmp, 0, bresp.length);
                        System.arraycopy(data, 0, tmp, bresp.length, rc);
                        bresp = tmp;
                    }

                    cl -= rc;
                } while (cl > 0);
            }
            is.close();
            
            if (bresp != null) {
                resp = new OCSPResp(bresp);
            }
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_REQ_SEND);
        }
        return resp;
    }


    public BouncyCastleNotaryServiceImpl(
            CRLService crlService, 
            CAService caService,
            String responderUrl, 
            boolean signRequests, 
            String p12file, 
            String p12password) {
        this.crlService = crlService;
        this.caService = caService;
        this.responderUrl = responderUrl;
        this.signRequests = signRequests;

        try {
            Provider prv = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
            Security.addProvider(prv);

            if (this.signRequests) {

                // load the cert & private key for OCSP signing
                if (p12file != null && p12password != null) {
                    FileInputStream fi = new FileInputStream(p12file);
                    KeyStore store = KeyStore.getInstance("PKCS12", "BC");
                    store.load(fi, p12password.toCharArray());
                    java.util.Enumeration<String> en = store.aliases();
                    // find the key alias
                    String pName = null;
                    while (en.hasMoreElements()) {
                        String n = en.nextElement();
                        if (store.isKeyEntry(n)) {
                            pName = n;
                        }
                    }
                    
                    signRequestKey = (PrivateKey) store.getKey(pName, null);
                    signRequestCert = (X509Certificate) store.getCertificate(pName);
                    
                    if (LOG.isInfoEnabled()) {
                        LOG.info("p12cert subject: " + signRequestCert.getSubjectX500Principal().getName("RFC1779"));
                        LOG.info("p12cert issuer: " + signRequestCert.getIssuerX500Principal().getName("RFC1779"));
                        LOG.info("p12cert serial: " + signRequestCert.getSerialNumber());
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public void setOCSPCerts(Set<String> certs) {
        try {
            for (String certFile : certs) {
                LOG.debug("Loading OCSP cert from file " + certFile);
                X509Certificate cert = DDUtils.readCertificate(certFile);
                String cn = DDUtils.getCommonName(cert.getSubjectX500Principal().getName("RFC1779"));
                LOG.debug("Loaded OCSP cert with cn=" + cn);
                ocspCerts.put(cn, cert);
            }
        } catch (DigiDocException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Checks if the certificate identified by this CN is
     * a known OCSP responders cert
     * @param cn certificates common name
     * @return true if this is a known OCSP cert
     */
    public boolean isKnownOCSPCert(String cn) {
        for (String key : ocspCerts.keySet()) {
            if (key.equals(cn)) {
                return true;
            }
        }
        
        return false;
    }
    

    /**
     * Converts a byte array to hex string
     * 
     * @param arr
     *            byte array input data
     * @return hex string
     */
    private static String bin2hex(byte[] arr) {
        StringBuffer sb = new StringBuffer();
        
        for (int i = 0; i < arr.length; i++) {
            String str = Integer.toHexString((int) arr[i]);
            if (str.length() == 2)
                sb.append(str);
            if (str.length() < 2) {
                sb.append("0");
                sb.append(str);
            }
            if (str.length() > 2)
                sb.append(str.substring(str.length() - 2));
        }
        
        return sb.toString();
    }
}
