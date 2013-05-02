package ee.sk.digidoc.services;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.URL;
import java.net.URLConnection;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;
import ee.sk.xmlenc.EncryptedData;

/**
 * Service class to handle generating M-ID signatures
 * using DigiDocService webservice
 * 
 * @author Veiko Sinivee
 */
public class DigiDocMIdServiceImpl {
    
    private static Logger LOG = Logger.getLogger(DigiDocMIdServiceImpl.class);
    
    public static final String STAT_OUTSTANDING_TRANSACTION = "OUTSTANDING_TRANSACTION";
    public static final String STAT_SIGNATURE = "SIGNATURE";
    public static final String STAT_ERROR = "ERROR";

    private static final String g_xmlHdr1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:d=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\" xmlns:mss=\"http://www.sk.ee:8096/MSSP_GW/MSSP_GW.wsdl\"><SOAP-ENV:Body SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><d:MobileCreateSignature>";
    private static final String g_xmlEnd1 = "</d:MobileCreateSignature></SOAP-ENV:Body></SOAP-ENV:Envelope>";
    private static final String g_xmlHdr2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:d=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\" xmlns:mss=\"http://www.sk.ee:8096/MSSP_GW/MSSP_GW.wsdl\"><SOAP-ENV:Body SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><d:GetMobileCreateSignatureStatus>";
    private static final String g_xmlEnd2 = "</d:GetMobileCreateSignatureStatus></SOAP-ENV:Body></SOAP-ENV:Envelope>";
    
    private static void addElement(StringBuffer xml, String tag, String value) {
        if (value != null && value.trim().length() > 0) {
            xml.append("<");
            xml.append(tag);
            xml.append(">");
            xml.append(value);
            xml.append("</");
            xml.append(tag);
            xml.append(">");
        }
    }
    
    private static String findElementValue(String msg, String tag) {
        int nIdx1 = 0, nIdx2 = 0;
        if (msg != null && tag != null) {
            nIdx1 = msg.indexOf("<" + tag);
            if (nIdx1 != -1) {
                while (msg.charAt(nIdx1) != '>')
                    nIdx1++;
                nIdx1++;
                nIdx2 = msg.indexOf("</" + tag, nIdx1);
                if (nIdx1 > 0 && nIdx2 > 0) return msg.substring(nIdx1, nIdx2);
            }
        }
        return null;
    }
    
    private static String findAttributeValue(String msg, String attr) {
        int nIdx1 = 0, nIdx2 = 0;
        if (msg != null && attr != null) {
            nIdx1 = msg.indexOf(attr);
            if (nIdx1 != -1) {
                while (msg.charAt(nIdx1) != '=')
                    nIdx1++;
                nIdx1++;
                if (msg.charAt(nIdx1) == '\"') nIdx1++;
                nIdx2 = msg.indexOf("\"", nIdx1);
                if (nIdx1 > 0 && nIdx2 > 0) return msg.substring(nIdx1, nIdx2);
            }
        }
        return null;
    }
    
    /**
     * Sends soap message and returns result
     * 
     * @param algorithm digest algorithm
     * @param digest digest value
     * @param url TSA server utl
     * @return response
     */
    private static String pullUrl(String url, String msg, String storename, String storepass, String storetype,
                    String ocspAuth, String ocspAuthUser, String ocspAuthPasswd) {
        try {
            URL uUrl = new URL(url);
            if (storename != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("https truststore: " + storename + "/" + storetype);
                }
                System.setProperty("javax.net.ssl.trustStore", storename);
                System.setProperty("javax.net.ssl.trustStorePassword", storepass);
                System.setProperty("javax.net.ssl.trustStoreType", storetype);
            }
            // http authentication
            if (ocspAuth != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("http auth: " + ocspAuthUser + "/" + ocspAuthPasswd);
                }
                HttpAuthenticator auth = new HttpAuthenticator(ocspAuthUser, ocspAuthPasswd);
                Authenticator.setDefault(auth);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Connecting to: " + url);
            }
            URLConnection con = uUrl.openConnection();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Conn opened: " + ((con != null) ? "OK" : "NULL"));
            }
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
            con.setRequestProperty("User-Agent", EncryptedData.LIB_NAME + " / " + EncryptedData.LIB_VERSION);
            con.setRequestProperty("SOAPAction", "");
            OutputStream os = con.getOutputStream();
            if (LOG.isDebugEnabled()) {
                LOG.debug("OS: " + ((os != null) ? "OK" : "NULL"));
            }
            os.write(msg.getBytes("UTF-8"));
            os.close();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Wrote: " + msg.length());
            }
            // read the response
            InputStream is = con.getInputStream();
            int cl = con.getContentLength();
            byte[] bresp = null;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Recv: " + cl + " bytes");
            }
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
            if (LOG.isDebugEnabled()) {
                LOG.debug("Received: " + ((bresp != null) ? bresp.length : 0) + " bytes");
            }
            String resp = new String(bresp, "UTF-8");
            return resp;
        } catch (Exception ex) {
            LOG.error("Soap error: " + ex);
        }
        return null;
    }
    
    /**
     * Starts M-ID signing session
     * 
     * @param sdoc signed doc to add a new signature to
     * @param sIdCode personal id code of signer
     * @param sPhoneNo phone number
     * @param sLang language
     * @param sServiceName service nama param to digidocservice
     * @param sManifest manifest of signature
     * @param sCity city
     * @param sState state or province
     * @param sZip postal index
     * @param sCountry country name
     * @param sbChallenge returned challenge code
     * @return session code
     * @throws DigiDocException
     */
    public static String ddsSign(SignedDoc sdoc, String sIdCode, String sPhoneNo, String sLang, String sServiceName,
                    String sManifest, String sCity, String sState, String sZip, String sCountry,
                    StringBuffer sbChallenge, String ddsUrl, String storename, String storepass, String storetype,
                    String ocspAuth, String ocspAuthUser, String ocspAuthPasswd) throws DigiDocException {
        String sSessCode = null;
        
        if (sdoc == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing SignedDoc object", null);
        if (sIdCode == null || sIdCode.trim().length() < 11)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid personal id-code",
                            null);
        if (sPhoneNo == null || sPhoneNo.trim().length() < 5) // min 5 kohaline mobiili nr ?
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid phone number", null);
        if (sCountry == null || sCountry.trim().length() < 2)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid country code", null);
        // compose soap msg
        StringBuffer sbMsg = new StringBuffer(g_xmlHdr1);
        addElement(sbMsg, "IDCode", sIdCode);
        addElement(sbMsg, "SignersCountry", sCountry);
        addElement(sbMsg, "PhoneNo", sPhoneNo);
        addElement(sbMsg, "Language", sLang);
        addElement(sbMsg, "ServiceName", sServiceName);
        addElement(sbMsg, "Role", sManifest);
        addElement(sbMsg, "City", sCity);
        addElement(sbMsg, "StateOrProvince", sState);
        addElement(sbMsg, "PostalCode", sZip);
        addElement(sbMsg, "CountryName", sCountry);
        sbMsg.append("<DataFiles>");
        for (int i = 0; i < sdoc.countDataFiles(); i++) {
            DataFile df = sdoc.getDataFile(i);
            sbMsg.append("<DataFileDigest>");
            addElement(sbMsg, "Id", df.getId());
            addElement(sbMsg, "DigestType", "sha1");
            String sHash = Base64Util.encode(df.getDigest());
            addElement(sbMsg, "DigestValue", sHash);
            sbMsg.append("</DataFileDigest>");
        }
        sbMsg.append("</DataFiles>");
        addElement(sbMsg, "Format", sdoc.getFormat());
        addElement(sbMsg, "Version", sdoc.getVersion());
        String sId = sdoc.getNewSignatureId();
        addElement(sbMsg, "SignatureID", sId);
        addElement(sbMsg, "MessagingMode", "asynchClientServer");
        addElement(sbMsg, "AsyncConfiguration", "0");
        sbMsg.append(g_xmlEnd1);
        // send soap message
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending:\n---\n" + sbMsg.toString() + "\n---\n");
        }
        String sResp = pullUrl(ddsUrl, sbMsg.toString(), storename, storepass, storetype, ocspAuth, ocspAuthUser,
                        ocspAuthPasswd);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Received:\n---\n" + sResp + "\n---\n");
        }
        if (sResp != null && sResp.trim().length() > 0) {
            sSessCode = findElementValue(sResp, "Sesscode");
            String s = findElementValue(sResp, "ChallengeID");
            if (s != null) {
                sbChallenge.append(s);
            }
        }
        return sSessCode;
    }
    
    /**
     * Sends soap message to query M-ID signing process status
     * 
     * @param sdoc signed doc object
     * @param sSesscode session code
     * @return status as string constant
     * @throws DigiDocException
     */
    public static String ddsGetStatus(SignedDoc sdoc, String sSesscode, String ddsUrl, String storename,
                    String storepass, String storetype, String ocspAuth, String ocspAuthUser, String ocspAuthPasswd)
                    throws DigiDocException {
        String sStatus = null;
        
        if (sdoc == null) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing SignedDoc object", null);
        }
        if (sSesscode == null || sSesscode.trim().length() == 0) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_SERVICE, "Missing or invalid  session code", null);
        }
        // compose soap msg
        StringBuffer sbMsg = new StringBuffer(g_xmlHdr2);
        addElement(sbMsg, "Sesscode", sSesscode);
        addElement(sbMsg, "WaitSignature", "false");
        sbMsg.append(g_xmlEnd2);
        // send soap message
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending:\n---\n" + sbMsg.toString() + "\n---\n");
        }
        String sResp = pullUrl(ddsUrl, sbMsg.toString(), storename, storepass, storetype, ocspAuth, ocspAuthUser,
                        ocspAuthPasswd);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Received:\n---\n" + sResp + "\n---\n");
        }
        if (sResp != null && sResp.trim().length() > 0) {
            sStatus = findElementValue(sResp, "Status");
            if (sStatus != null && sStatus.equals(STAT_SIGNATURE)) {
                String s = findElementValue(sResp, "Signature");
                if (s != null) {
                    String sSig = ConvertUtils.unescapeXmlSymbols(s);
                    String sId = findAttributeValue(sSig, "Id");
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signature: " + sId + "\n---\n" + sSig + "\n---\n");
                    }
                    Signature sig = new Signature(sdoc);
                    sig.setId(sId);
                    try {
                        sig.setOrigContent(sSig.getBytes("UTF-8"));
                    } catch (Exception ex) {
                        LOG.error("Error adding signature: " + ex);
                        DigiDocException.handleException(ex, DigiDocException.ERR_DIGIDOC_SERVICE);
                    }
                    sdoc.addSignature(sig);
                }
            }
        }
        return sStatus;
    }
}
