package ee.sk.digidoc.services;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

import ee.sk.digidoc.CertID;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Notary;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;
import ee.sk.xmlenc.EncryptedData;

public class BouncyCastleNotaryServiceImpl implements NotaryService {

    private static final String nonceOid = "1.3.6.1.5.5.7.48.1.2";
    //    private static final String sha1NoSign = "1.3.14.3.2.26";
    //    private static final String subjectKeyIdentifier = "2.5.29.14";
    private static final int V_ASN1_OCTET_STRING = 4;
    private static final Logger LOG = Logger.getLogger(BouncyCastleNotaryServiceImpl.class);
    
    private boolean signRequests;
    private X509Certificate signRequestCert;
    private PrivateKey signRequestKey;
    
    private boolean useOCSP = true;
    private boolean checkOcspNonce = false;
    private String responderUrl;
    private int ocspTimeout = -1;

    private final CRLService crlService;
    private final TrustService trustService;
    
    public void setUseOCSP(boolean useOCSP) {
        this.useOCSP = useOCSP;
    }
    
    public void setResponderUrl(String responderUrl) {
        this.responderUrl = responderUrl;
    }
    
    public void setSignRequests(boolean signRequests) {
        this.signRequests = signRequests;
    }
    
    public void setOcspTimeout(int timeout) {
        this.ocspTimeout = timeout;
    }
    
    public void setCheckOcspNonce(boolean checkOcspNonce) {
        this.checkOcspNonce = checkOcspNonce;
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
        if (LOG.isInfoEnabled()) {
            LOG.info("Find responder for: " + responderCN + " cert: " + specificCertNr);
        }
        
        return trustService.findOcspByCN(responderCN);
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
                    X509Certificate notaryCert, String notId, String ocspUrl, String httpFrom, String format,
                    String formatVer) throws DigiDocException {
        Notary not = null;
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("getConfirmation, nonce " + Base64Util.encode(nonce, 0) + " cert: "
                                + ((signersCert != null) ? signersCert.getSerialNumber().toString() : "NULL") + " CA: "
                                + ((caCert != null) ? caCert.getSerialNumber().toString() : "NULL") + " responder: "
                                + ((notaryCert != null) ? notaryCert.getSerialNumber().toString() : "NULL")
                                + " notId: " + notId + " signRequest: " + signRequests);
                LOG.debug("Check cert: " + ((signersCert != null) ? signersCert.getSubjectDN().getName() : "NULL"));
                LOG.debug("Check CA cert: " + ((caCert != null) ? caCert.getSubjectDN().getName() : "NULL"));
            }
            
            // create the request - sign the request if necessary
            OCSPReq req = createOCSPRequest(nonce, signersCert, caCert, signRequests);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }

            // send it
            OCSPResp resp = sendRequestToUrl(req, ocspUrl, httpFrom, format, formatVer);
            // debugWriteFile("resp.der", resp.getEncoded());
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }
            
            // check response status
            verifyRespStatus(resp);
            // check the result
            not = parseAndVerifyResponse(null, notId, signersCert, resp, nonce, notaryCert, caCert);
            
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
            byte[] nonce = DDUtils.digestOfType(sig.getSignatureValue().getValue(), sig.getSignedDoc().getFormat()
                            .equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE : DDUtils.SHA1_DIGEST_TYPE);
            X509Certificate notaryCert = null;
            if (sig.getUnsignedProperties() != null)
                notaryCert = sig.getUnsignedProperties().getRespondersCertificate();
            // check the result
            not = getConfirmation(nonce, signersCert, caCert, notaryCert, notId, responderUrl, sig.getHttpFrom(), sig
                            .getSignedDoc().getFormat(), sig.getSignedDoc().getVersion());
            // add cert to signature
            if (notaryCert == null && sig != null && sig.getUnsignedProperties() != null) {
                OCSPResp resp = new OCSPResp(not.getOcspResponseData());
                if (resp != null && resp.getResponseObject() != null) {
                    String respId = responderIDtoString((BasicOCSPResp) resp.getResponseObject());
                    notaryCert = trustService.findOcspByCN(DDUtils.getCommonName(respId));
                    if (LOG.isDebugEnabled())
                        LOG.debug("Using notary cert: "
                                        + ((notaryCert != null) ? notaryCert.getSubjectDN().getName() : "NULL"));
                    if (notaryCert != null && !sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_XADES)) {
                        sig.getUnsignedProperties().setRespondersCertificate(notaryCert);
                    }
                    CertID cid = new CertID(sig, notaryCert, ee.sk.digidoc.CertID.CERTID_TYPE_RESPONDER);
                    sig.addCertID(cid);
                    cid.setUri("#" + sig.getId() + "-RESPONDER_CERT");
                    if (notaryCert == null)
                        throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP responders cert not found",
                                        null);

                }
            }
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return not;
    }
    
    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response
     * 
     * @param sig Signature object.
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @param notaryCert OCSP responders cert
     * @param ocspUrl OCSP responders url
     * @returns Notary object
     */
    public Notary getConfirmation(Signature sig, X509Certificate signersCert, X509Certificate caCert,
                    X509Certificate notaryCert, String ocspUrl) throws DigiDocException {
        Notary not = null;
        try {
            String notId = sig.getId().replace('S', 'N');
            
            // calculate the nonce
            byte[] nonce = DDUtils.digestOfType(sig.getSignatureValue().getValue(), sig.getSignedDoc().getFormat()
                            .equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE : DDUtils.SHA1_DIGEST_TYPE);
            
            if (notaryCert == null && sig.getUnsignedProperties() != null)
                notaryCert = sig.getUnsignedProperties().getRespondersCertificate();
            
            // check the result
            not = getConfirmation(nonce, signersCert, caCert, notaryCert, notId, ocspUrl, sig.getHttpFrom(), sig
                            .getSignedDoc().getFormat(), sig.getSignedDoc().getVersion());
            
            if (sig != null && not != null && sig.getUnsignedProperties() != null)
                sig.getUnsignedProperties().setNotary(not);
            
            // add cert to signature
            if (notaryCert == null && sig != null && sig.getUnsignedProperties() != null
                            && sig.getUnsignedProperties().getNotary() != null) {
                OCSPResp resp = new OCSPResp(sig.getUnsignedProperties().getNotary().getOcspResponseData());
                if (resp != null && resp.getResponseObject() != null && notaryCert == null) {
                    String respId = responderIDtoString((BasicOCSPResp) resp.getResponseObject());
                    notaryCert = trustService.findOcspByCN(DDUtils.getCommonName(respId));
                    if (notaryCert != null) {
                        sig.getUnsignedProperties().setRespondersCertificate(notaryCert);
                        CertID cid = new CertID(sig, notaryCert, ee.sk.digidoc.CertID.CERTID_TYPE_RESPONDER);
                        sig.addCertID(cid);
                        cid.setUri("#" + sig.getId() + "-RESPONDER_CERT");
                    }
                }
            }
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return not;
    }

    private String composeHttpFrom() {
        // set HTTP_FROM to some value
        String from = null;
        try {
            NetworkInterface ni = null;
            Enumeration<NetworkInterface> eNi = NetworkInterface.getNetworkInterfaces();
            if (eNi != null && eNi.hasMoreElements()) ni = (NetworkInterface) eNi.nextElement();
            if (ni != null) {
                InetAddress ia = null;
                Enumeration<InetAddress> eA = ni.getInetAddresses();
                if (eA != null && eA.hasMoreElements()) ia = (InetAddress) eA.nextElement();
                if (ia != null) from = ia.getHostAddress();
            }
        } catch (Exception ex2) {
            LOG.error("Error finding ip-adr: " + ex2);
        }
        return from;
    }

    /**
     * Verifies the certificate by creating an OCSP request
     * and sending it to SK server.
     * 
     * @param cert certificate to verify
     * @param httpFrom HTTP_FROM optional argument
     * @throws DigiDocException if the certificate is not valid
     * @return ocsp response
     */
    public OCSPResp checkCertificate(X509Certificate cert) throws DigiDocException {
        return checkCertificate(cert, composeHttpFrom());
    }
    
    /**
     * Verifies the certificate by creating an OCSP request
     * and sending it to SK server.
     * 
     * @param cert certificate to verify
     * @param httpFrom HTTP_FROM optional argument
     * @throws DigiDocException if the certificate is not valid
     * @return ocsp response
     */
    public OCSPResp checkCertificate(X509Certificate cert, String httpFrom) throws DigiDocException {
        OCSPResp resp = null;
        try {
            if (useOCSP) {
                // create the request
                X509Certificate caCert = trustService.findCaForCert(cert);
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Find CA for: "
                                    + DDUtils.getCommonName(DDUtils.convX509Name(cert.getIssuerX500Principal())));
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
                String ocspUrl = trustService.findOcspUrlForCert(cert, 0);
                resp = sendRequestToUrl(req, ocspUrl, httpFrom, null, null);
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got ocsp response: " + resp.getEncoded().length + " bytes");
                    LOG.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
                }
                
                // check response status
                verifyRespStatus(resp);
                // now read the info from the response
                BasicOCSPResp basResp = (BasicOCSPResp) resp.getResponseObject();
                
                byte[] nonce2 = getNonce(basResp, null);
                
                if (LOG.isDebugEnabled())
                    LOG.debug("Nonce1: "
                                    + ((nonce1 != null) ? ConvertUtils.bin2hex(nonce1) + " len: " + nonce1.length
                                                    : "NULL")
                                    + " nonce2: "
                                    + ((nonce2 != null) ? ConvertUtils.bin2hex(nonce2) + " len: " + nonce2.length
                                                    : "NULL"));

                if (!DDUtils.compareDigests(nonce1, nonce2)) {
                    throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                                    "Invalid nonce value! Possible replay attack!", null);
                }

                // verify the response
                try {
                    String respId = responderIDtoString(basResp);
                    
                    X509Certificate notaryCert = getNotaryCert(DDUtils.getCommonName(respId), null);
                    
                    boolean ok = false;
                    
                    if (notaryCert != null)
                        ok = basResp.verify(notaryCert.getPublicKey(), "BC");
                    else
                        throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "Responder cert not found for: "
                                        + respId, null);
                    if (ok)
                        throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP verification error!", null);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using notary cert: "
                                        + ((notaryCert != null) ? notaryCert.getSubjectDN().getName() : "NULL"));
                    }
                } catch (Exception ex) {
                    LOG.error("OCSP Signature verification error!!!", ex);
                    DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
                }
                
                // check the response about this certificate
                checkCertStatus(cert, basResp, caCert);
            } else {
                crlService.checkCertificate(cert, new Date());
            }
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return resp;
    }
    
    /**
     * Verifies the certificate by creating an OCSP request
     * and sending it to ocsp server.
     * 
     * @param cert certificate to verify
     * @param caCert CA certificate
     * @param url OCSP responder url
     * @param bosNonce buffer to return generated nonce
     * @param sbRespId buffer to return responderId field
     * @param bosReq buffer to return ocsp request
     * @param httpFrom http_from atribute
     * @throws DigiDocException if the certificate is not valid
     */
    public OCSPResp sendCertOcsp(X509Certificate cert, X509Certificate caCert, String url,
                    ByteArrayOutputStream bosNonce, StringBuffer sbRespId, ByteArrayOutputStream bosReq, String httpFrom)
                    throws DigiDocException {
        try {
            OCSPResp resp = null;
            // create the request
            if (LOG.isDebugEnabled()) {
                LOG.debug("Find CA for: " + DDUtils.getCommonName(DDUtils.convX509Name(cert.getIssuerX500Principal())));
                LOG.debug("Check cert: " + cert.getSubjectDN().getName());
                LOG.debug("Check CA cert: " + caCert.getSubjectDN().getName());
            }
            String strTime = new java.util.Date().toString();
            byte[] nonce1 = DDUtils.digest(strTime.getBytes());
            
            bosNonce.write(nonce1);
            OCSPReq req = createOCSPRequest(nonce1, cert, caCert, false);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Sending ocsp request: " + req.getEncoded().length + " bytes");
                LOG.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }
            
            if (req != null && bosReq != null) bosReq.write(req.getEncoded());
            
            resp = sendRequestToUrl(req, url, httpFrom, null, null);
            
            if (resp != null) {
                BasicOCSPResp basResp = (BasicOCSPResp) resp.getResponseObject();
                String sRespId = responderIDtoString(basResp);
                if (sRespId != null) sbRespId.append(sRespId);
            }
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Got ocsp response: " + ((resp != null) ? resp.getEncoded().length : 0) + " bytes");
                if (resp != null) LOG.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }

            return resp;
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return null;
    }
    
    /**
     * Verifies OCSP response by given responder cert. Checks actual certificate status.
     * 
     * @param resp ocsp response
     * @param cert certificate to check
     * @param ocspCert OCSP responders cert
     * @param nonce1 initial nonce value
     * @return true if verified ok
     * @throws DigiDocException
     */
    public boolean checkCertOcsp(OCSPResp resp, X509Certificate cert, X509Certificate ocspCert, byte[] nonce1,
                    X509Certificate caCert) throws DigiDocException {
        try {
            // check response status
            verifyRespStatus(resp);
            
            BasicOCSPResp basResp = (BasicOCSPResp) resp.getResponseObject();
            byte[] nonce2 = getNonce(basResp, null);
            if (!DDUtils.compareDigests(nonce1, nonce2))
                throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                                "Invalid nonce value! Possible replay attack!", null);
            // verify the response
            boolean ok = false;

            try {
                responderIDtoString(basResp);
                ok = basResp.verify(ocspCert.getPublicKey(), "BC");
            } catch (Exception ex) {
                LOG.error("OCSP Signature verification error!!!", ex);
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }

            // check the response about this certificate
            checkCertStatus(cert, basResp, caCert);

            return ok;
        } catch (DigiDocException ex) {
            throw ex;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        }
        return false;
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
                    byte[] nonce1, X509Certificate notaryCert, X509Certificate caCert) throws DigiDocException {
        Notary not = null;

        // check the result
        if (resp == null || resp.getStatus() != OCSPRespStatus.SUCCESSFUL) {
            throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL, "OCSP response unsuccessfull!", null);
        }
        
        try {
            // now read the info from the response
            BasicOCSPResp basResp = (BasicOCSPResp) resp.getResponseObject();
            // find real notary cert suitable for this response
            String respondIDstr = responderIDtoString(basResp);
            
            if (notaryCert == null) {
                String CN = DDUtils.getCommonName(respondIDstr);
                notaryCert = getNotaryCert(CN, null);
                if (LOG.isDebugEnabled())
                    LOG.debug("Find notary cert: " + CN + " found: " + ((notaryCert != null) ? "OK" : "NULL"));
            }
            if (notaryCert == null) {
                throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "Notary cert not found for: "
                                + respondIDstr, null);
            }
            
            // verify the response
            boolean bOk = false;
            try {
                bOk = basResp.verify(notaryCert.getPublicKey(), "BC");
            } catch (Exception ex) {
                LOG.error("OCSP Signature verification error!!!", ex);
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            
            if (!bOk) {
                LOG.error("OCSP Signature verification error!!!");
                throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP Signature verification error!!!",
                                null);
            }
            
            if (LOG.isInfoEnabled() && notaryCert != null) {
                LOG.info("Using responder cert: " + notaryCert.getSerialNumber().toString());
            }

            // done't care about SingleResponses because we have
            // only one response and the whole response was successful
            // but we should verify that the nonce hasn't changed
            byte[] nonce2 = getNonce(basResp, (sig != null) ? sig.getSignedDoc() : null);
            boolean ok = true;
            
            if (nonce1 == null || nonce2 == null || nonce1.length != nonce2.length) {
                ok = false;
            } else {
                for (int i = 0; i < nonce1.length; i++) {
                    if (nonce1[i] != nonce2[i]) {
                        ok = false;
                    }
                }
            }
            
            if (!ok && sig != null) {
                LOG.error("DDOC ver: " + sig.getSignedDoc().getVersion() + " SIG: " + sig.getId() + " Real nonce: "
                                + Base64Util.encode(nonce2, 0) + " My nonce: " + Base64Util.encode(nonce1, 0));
                throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                                "OCSP response's nonce doesn't match the requests nonce!", null);
            }
            
            // check the response on our cert
            checkCertStatus(signersCert, basResp, caCert);
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
        checkCertStatus(sig.getKeyInfo().getSignersCertificate(), basResp, null);
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
    private void checkCertStatus(X509Certificate cert, BasicOCSPResp basResp, X509Certificate caCert)
                    throws DigiDocException {
        try {
            if (LOG.isDebugEnabled())
                LOG.debug("Checking response status, CERT: "
                                + ((cert != null) ? cert.getSubjectDN().getName() : "NULL")
                                + " SEARCH: "
                                + ((cert != null) ? DDUtils.getCommonName(DDUtils.convX509Name(cert
                                                .getIssuerX500Principal())) : "NULL"));
            
            if (cert == null)
                throw new DigiDocException(DigiDocException.ERR_CERT_UNKNOWN,
                                "No certificate to check! Error reading certificate from file?", null);
            
            if (caCert == null) caCert = trustService.findCaForCert(cert);

            if (LOG.isDebugEnabled()) {
                LOG.debug("CA cert: " + ((caCert == null) ? "NULL" : caCert.getSubjectDN().getName()));
                LOG.debug("RESP: " + basResp);
                LOG.debug("CERT: "
                                + cert.getSubjectDN().getName()
                                + " ISSUER: "
                                + DDUtils.convX509Name(cert.getIssuerX500Principal())
                                + " nr: "
                                + ((caCert != null) ? ConvertUtils.bin2hex(caCert.getSerialNumber().toByteArray())
                                                : "NULL"));
            }
            
            if (caCert == null)
                throw new DigiDocException(DigiDocException.ERR_CERT_UNKNOWN, "Unknown CA cert: "
                                + cert.getIssuerDN().getName(), null);

            SingleResp[] sresp = basResp.getResponses();
            CertificateID rc = creatCertReq(cert, caCert);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Search alg: " + rc.getHashAlgOID() + " cert serial: " + cert.getSerialNumber().toString()
                                + " serial: " + rc.getSerialNumber() + " issuer: "
                                + Base64Util.encode(rc.getIssuerKeyHash()) + " subject: "
                                + Base64Util.encode(rc.getIssuerNameHash()));
            }

            boolean ok = false;
            for (int i = 0; i < sresp.length; i++) {
                CertificateID id = sresp[i].getCertID();
                if (id != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Got alg: " + id.getHashAlgOID() + " serial: " + id.getSerialNumber() + " issuer: "
                                        + Base64Util.encode(id.getIssuerKeyHash()) + " subject: "
                                        + Base64Util.encode(id.getIssuerNameHash()));
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
            
            List<X509Certificate> notaryCerts = null;
            
            if (sig != null && sig.getUnsignedProperties() != null
                            && sig.getUnsignedProperties().getRespondersCertificate() == null) {
                throw new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                                "OCSP responders certificate is required!", null);
            }
            
            // verify the response
            try {
                String respondIDstr = responderIDtoString(basResp);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SIG: " + ((sig == null) ? "NULL" : sig.getId()));
                    LOG.debug("UP: "
                                    + ((sig.getUnsignedProperties() == null) ? "NULL" : "OK: "
                                                    + sig.getUnsignedProperties().getNotary().getId()));
                    LOG.debug("RESP-CERT: "
                                    + ((sig.getUnsignedProperties().getRespondersCertificate() == null) ? "NULL" : "OK"));
                    LOG.debug("RESP-ID: " + respondIDstr);
                    CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
                    
                    if (cid != null)
                        LOG.debug("CID: " + cid.getType() + " id: " + cid.getId() + ", " + cid.getSerial()
                                        + " issuer: " + cid.getIssuer());
                    LOG.debug("RESP: " + Base64Util.encode(resp.getEncoded()));
                }
                if (notaryCerts == null && sig != null) {
                    String ddocRespCertNr = sig.getUnsignedProperties().getRespondersCertificate().getSerialNumber()
                                    .toString();
                    String respSrch = respondIDstr;
                    if ((respSrch.indexOf("CN") != -1)) respSrch = DDUtils.getCommonName(respondIDstr);
                    if (respSrch.startsWith("byKey: ")) respSrch = respSrch.substring("byKey: ".length());
                    int n1 = respSrch.indexOf(',');
                    if (n1 > 0) respSrch = respSrch.substring(0, n1);
                    if (LOG.isDebugEnabled()) LOG.debug("Search not cert by: " + respSrch + " nr: " + ddocRespCertNr);
                    notaryCerts = trustService.findOcspsByCNAndNr(respSrch, ddocRespCertNr);
                }
                
                if (notaryCerts == null || notaryCerts.size() == 0)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_RECPONDER_NOT_TRUSTED,
                                    "No certificate for responder: \'" + respondIDstr
                                                    + "\' found in local certificate store!", null);
                
                boolean ok = false;
                
                if (notaryCerts != null) {
                    for (X509Certificate cert : notaryCerts) {
                        if (LOG.isDebugEnabled())
                            LOG.debug("Verify using responders cert: "
                                            + ((cert != null) ? DDUtils.getCommonName(cert.getSubjectDN().getName())
                                                            + " nr: " + cert.getSerialNumber().toString() : "NULL"));
                        ok = basResp.verify(cert.getPublicKey(), "BC");
                        if (LOG.isDebugEnabled())
                            LOG.debug("OCSP resp: "
                                            + ((basResp != null) ? responderIDtoString(basResp) : "NULL")
                                            + " verify using: "
                                            + ((cert != null) ? DDUtils.getCommonName(cert.getSubjectDN().getName())
                                                            : "NULL") + " verify: " + ok);
                    }
                }
                
                if (!ok)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "OCSP verification error!", null);
                
            } catch (Exception ex) {
                LOG.error("Signature verification error: " + ex);
                ex.printStackTrace();
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            }
            // done't care about SingleResponses because we have
            // only one response and the whole response was successfull
            // but we should verify that the nonce hasn't changed
            // calculate the nonce
            byte[] nonce1 = DDUtils.digestOfType(sig.getSignatureValue().getValue(), sig.getSignedDoc().getFormat()
                            .equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE : DDUtils.SHA1_DIGEST_TYPE);
            byte[] nonce2 = getNonce(basResp, sig.getSignedDoc());
            boolean bOk = true;
            if (nonce1 == null || nonce2 == null || nonce1.length != nonce2.length) bOk = false;
            for (int i = 0; (nonce1 != null) && (nonce2 != null) && (i < nonce1.length); i++)
                if (nonce1[i] != nonce2[i]) bOk = false;
            if (!bOk && sig.getSignedDoc() != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SigVal\n---\n" + Base64Util.encode(sig.getSignatureValue().getValue())
                                    + "\n---\nOCSP\n---\n" + Base64Util.encode(not.getOcspResponseData()) + "\n---\n");
                    LOG.debug("DDOC ver: " + sig.getSignedDoc().getVersion() + " SIG: " + sig.getId() + " NOT: "
                                    + not.getId() + " Real nonce: "
                                    + ((nonce2 != null) ? Base64Util.encode(nonce2, 0) : "NULL") + " noncelen: "
                                    + ((nonce2 != null) ? nonce2.length : 0) + " SigVal hash: "
                                    + Base64Util.encode(nonce1, 0) + " SigVal hash hex: "
                                    + ConvertUtils.bin2hex(nonce1) + " svlen: "
                                    + ((nonce1 != null) ? nonce1.length : 0));
                    LOG.debug("SIG:\n---\n" + sig.toString() + "\n--\n");
                }
                throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                                "OCSP response's nonce doesn't match the requests nonce!", null);
            }
            if (LOG.isDebugEnabled()) LOG.debug("Verify not: " + not.getId());
            
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

            if (o instanceof DEROctetString) {
                DEROctetString oc = (DEROctetString) o;
                return "byKey: " + ConvertUtils.bin2hex(oc.getOctets());
            } else {
                X509Name name = new X509Name((ASN1Sequence) o);
                return "byName: " + name.toString();
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
    private byte[] getNonce(BasicOCSPResp basResp, SignedDoc sdoc) {
        if (basResp != null) {
            X509Extensions ext = basResp.getResponseExtensions();
            X509Extension ex1 = ext.getExtension(new DERObjectIdentifier(nonceOid));
            byte[] nonce2 = ex1.getValue().getOctets();
            if (LOG.isDebugEnabled())
                LOG.debug("Nonce hex: " + ConvertUtils.bin2hex(nonce2) + " b64: " + Base64Util.encode(nonce2)
                                + " len: " + nonce2.length);
            boolean bAsn1 = false;
            if (sdoc != null && sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) || sdoc == null) {
                if (nonce2 != null && nonce2.length == 22 /* && nonce2[0] == V_ASN1_OCTET_STRING */) {
                    byte[] b = new byte[20];
                    System.arraycopy(nonce2, nonce2.length - 20, b, 0, 20);
                    nonce2 = b;
                    bAsn1 = true;
                }
            }
            if (sdoc != null && sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                if (nonce2 != null && nonce2.length == 34) {
                    byte[] b = new byte[32];
                    System.arraycopy(nonce2, nonce2.length - 32, b, 0, 32);
                    nonce2 = b;
                    bAsn1 = true;
                }
            }
            if (!bAsn1 && checkOcspNonce) {
                LOG.error("Invalid nonce: " + ConvertUtils.bin2hex(nonce2) + " length: " + nonce2.length + "!");
                return null;
            }
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
     * @throws OCSPException
     */
    private CertificateID creatCertReq(X509Certificate signersCert, X509Certificate caCert)
                    throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException,
                    DigiDocException, OCSPException {
        return new CertificateID(CertificateID.HASH_SHA1, caCert, signersCert.getSerialNumber());
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
                LOG.debug("Request for: " + certId.getHashAlgOID() + " serial: " + certId.getSerialNumber()
                                + " issuer: " + Base64Util.encode(certId.getIssuerKeyHash()) + " subject: "
                                + Base64Util.encode(certId.getIssuerNameHash()) + " nonce: "
                                + ConvertUtils.bin2hex(nonce));
            }

            ocspRequest.addRequest(certId);
            if (nonce != null) {
                if (nonce[0] != V_ASN1_OCTET_STRING) {
                    byte[] b = new byte[nonce.length + 2];
                    b[0] = V_ASN1_OCTET_STRING;
                    b[1] = (byte) nonce.length;
                    System.arraycopy(nonce, 0, b, 2, nonce.length);
                    if (LOG.isDebugEnabled())
                        LOG.debug("Nonce in: " + ConvertUtils.bin2hex(nonce) + " with-asn1: " + ConvertUtils.bin2hex(b));
                    nonce = b;
                }
                Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
                Vector<X509Extension> values = new Vector<X509Extension>();
                oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                values.add(new X509Extension(false, new DEROctetString(nonce)));
                X509Extensions ret = new X509Extensions(oids, values);
                ocspRequest.setRequestExtensions(ret);
            }

            GeneralName name = null;
            if (bSigned) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SignCert: " + ((signRequestCert != null) ? signRequestCert.toString() : "NULL"));
                }
                if (signRequestCert == null)
                    throw new DigiDocException(
                                    DigiDocException.ERR_INVALID_CONFIG,
                                    "Invalid config file! Attempting to sign ocsp request but PKCS#12 token not configured!",
                                    null);

                name = new GeneralName(PrincipalUtil.getSubjectX509Principal(signRequestCert));
            } else {
                if (signersCert == null)
                    throw new DigiDocException(DigiDocException.ERR_OCSP_SIGN, "Signature owners certificate is NULL!",
                                    null);
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

    private String getUserInfo(String format, String formatVer) {
        StringBuffer sb = null;
        try {
            sb = new StringBuffer("LIB ");
            sb.append(EncryptedData.LIB_NAME);
            sb.append("/");
            sb.append(EncryptedData.LIB_VERSION);
            if (format != null && formatVer != null) {
                sb.append(" format: ");
                sb.append(format);
                sb.append("/");
                sb.append(formatVer);
            }
            sb.append(" Java: ");
            sb.append(System.getProperty("java.version"));
            sb.append("/");
            sb.append(System.getProperty("java.vendor"));
            sb.append(" OS: ");
            sb.append(System.getProperty("os.name"));
            sb.append("/");
            sb.append(System.getProperty("os.arch"));
            sb.append("/");
            sb.append(System.getProperty("os.version"));
            sb.append(" JVM: ");
            sb.append(System.getProperty("java.vm.name"));
            sb.append("/");
            sb.append(System.getProperty("java.vm.vendor"));
            sb.append("/");
            sb.append(System.getProperty("java.vm.version"));
        } catch (Throwable ex) {
            LOG.error("Error reading java system properties: " + ex);
        }
        return ((sb != null) ? sb.toString() : null);
    }

    /**
     * Sends the OCSP request to Notary and
     * retrieves the response
     * 
     * @param req OCSP request
     * @param url OCSP responder url
     * @param httpFrom HTTP_FROM value (optional)
     * @returns OCSP response
     */
    private OCSPResp sendRequestToUrl(OCSPReq req, String ocspUrl, String httpFrom, String format, String formatVer)
                    throws DigiDocException {
        OCSPResp resp = null;

        try {
            byte[] breq = req.getEncoded();
            URL url = new URL(ocspUrl);
            if (LOG.isDebugEnabled()) LOG.debug("Connecting to ocsp url: " + url);
            URLConnection con = url.openConnection();
            int timeout = con.getConnectTimeout();
            if (LOG.isDebugEnabled()) LOG.debug("Default connection timeout: " + timeout + " [ms]");
            if (ocspTimeout >= 0) {
                if (LOG.isDebugEnabled()) LOG.debug("Setting connection timeout to: " + ocspTimeout + " [ms]");
                con.setConnectTimeout(ocspTimeout);
            }
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            String userInfo = getUserInfo(format, formatVer);
            if (userInfo != null) {
                if (LOG.isDebugEnabled()) LOG.debug("User-Agent: " + userInfo);
                con.setRequestProperty("User-Agent", userInfo);
            }
            if (httpFrom != null && httpFrom.trim().length() > 0) {
                if (LOG.isDebugEnabled()) LOG.debug("HTTP_FROM: " + httpFrom);
                con.setRequestProperty("HTTP_FROM", httpFrom);
            }
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
    
    public BouncyCastleNotaryServiceImpl(CRLService crlService, TrustService trustService, String responderUrl,
                    boolean signRequests, String p12file, String p12password, int ocspTimeout, boolean checkOcspNonce) {
        this.crlService = crlService;
        this.trustService = trustService;
        this.responderUrl = responderUrl;
        this.signRequests = signRequests;
        this.ocspTimeout = ocspTimeout;
        this.checkOcspNonce = checkOcspNonce;

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

    /**
     * Checks if the certificate identified by this CN is
     * a known OCSP responders cert
     * 
     * @param cn certificates common name
     * @return true if this is a known OCSP cert
     */
    public boolean isKnownOCSPCert(String cn) {
        if (trustService.findOcspByCN(cn) != null) {
            return true;
        }
        return false;
    }
}
