package ee.sk.digidoc.services;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.TimestampInfo;
import ee.sk.utils.Base64Util;
import ee.sk.utils.DDUtils;

public class BouncyCastleTimestampService implements TimestampService {

    private static final Logger LOG = Logger.getLogger(BouncyCastleTimestampService.class);

    private String ocspAuthUser;
    private String ocspAuthPasswd;
    
    public void setAuthUser(String user) {
        this.ocspAuthUser = user;
    }
    
    public void setAuthPasswd(String passw) {
        this.ocspAuthPasswd = passw;
    }

    /**
     * Verifies this one timestamp
     * 
     * @param ts TimestampInfo object
     * @param tsaCert TSA certificate
     * @returns result of verification
     */
    public boolean verifyTimestamp(TimestampInfo ts, X509Certificate tsaCert) throws DigiDocException {
        boolean ok = false;
        
        TimeStampToken tsToken = ts.getTimeStampToken();

        if (LOG.isDebugEnabled())
            LOG.debug("Verifying TS: " + ts.getId() + " nr: " + ts.getSerialNumber() + " msg-imprint: "
                            + Base64Util.encode(tsToken.getTimeStampInfo().getMessageImprintDigest())
                            + " real digest: " + Base64Util.encode(ts.getHash()));
        
        if (!DDUtils.compareDigests(ts.getMessageImprint(), ts.getHash())) {
            LOG.error("TS digest: " + Base64Util.encode(ts.getMessageImprint()) + " real digest: "
                            + Base64Util.encode(ts.getHash()));
            throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                            "Bad digest for timestamp: " + ts.getId(), null);
        }
        
        if (tsToken != null) {
            try {
                tsToken.validate(tsaCert, "BC");
                ok = true;
            } catch (Exception ex) {
                ok = false;
                LOG.error("Timestamp verification error: " + ex);
                throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY, "Invalid timestamp: "
                                + ex.getMessage(), ex);
            }
        }
        
        return ok;
    }
    
    /**
     * Verifies all timestamps in this signature and
     * return a list of errors.
     * 
     * @param sig signature to verify timestamps
     * @return list of errors. Empty if no errors.
     * @throws DigiDocException
     */
    public List<DigiDocException> verifySignaturesTimestamps(Signature sig) {
        Date d1 = null, d2 = null;
        List<DigiDocException> errs = new ArrayList<DigiDocException>();
        List<X509Certificate> tsaCerts = sig.findTSACerts();
        for (int t = 0; t < sig.countTimestampInfos(); t++) {
            TimestampInfo ts = sig.getTimestampInfo(t);
            if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE) d1 = ts.getTime();
            if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS) d2 = ts.getTime();
            boolean bVerified = false;
            DigiDocException ex2 = null;
            for (int j = 0; j < tsaCerts.size(); j++) {
                X509Certificate tsaCert = (X509Certificate) tsaCerts.get(j);
                if (LOG.isDebugEnabled())
                    LOG.debug("Verifying TS: " + ts.getId() + " with: "
                                    + DDUtils.getCommonName(tsaCert.getSubjectDN().getName()));
                // try verifying with all possible TSA certs
                try {
                    if (verifyTimestamp(ts, tsaCert)) {
                        bVerified = true;
                        if (LOG.isDebugEnabled()) LOG.debug("TS: " + ts.getId() + " - OK");
                        break;
                    } else {
                        LOG.error("TS: " + ts.getId() + " - NOK");
                    }
                } catch (DigiDocException ex) {
                    ex2 = ex;
                    LOG.error("TS: " + ts.getId() + " - ERROR: " + ex);
                    //ex.printStackTrace(System.err);
                }
            }
            if (!bVerified) {
                errs.add(ex2);
            }
        }
        // now check that SignatureTimeStamp is before SigAndRefsTimeStamp
        if (d1 != null && d2 != null) {
            if (LOG.isDebugEnabled()) LOG.debug("SignatureTimeStamp: " + d1 + " SigAndRefsTimeStamp: " + d2);
            if (d1.after(d2)) {
                DigiDocException ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                                "SignatureTimeStamp time must be before SigAndRefsTimeStamp time!", null);
                errs.add(ex);
            }
        }
        return errs;
    }
    
    /**
     * Generates a TS request and sends it to server. Returns answer if obtained
     * 
     * @param algorithm digest algorithm
     * @param digest digest value
     * @param url TSA server utl
     * @return response
     */
    public TimeStampResponse requestTimestamp(String algorithm, byte[] digest, String url) {
        try {
            if (LOG.isDebugEnabled())
                LOG.debug("TS req: " + algorithm + " dig-len: " + ((digest != null) ? digest.length : 0) + " url: "
                                + url + " digest: " + Base64Util.encode(digest));
            
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            gen.setCertReq(true);
            TimeStampRequest req = gen.generate(algorithm, digest);
            
            if (LOG.isDebugEnabled())
                LOG.debug("TS req nonce: "
                                + ((req.getNonce() != null) ? req.getNonce().toString() : "NULL")
                                + " msg-imprint: "
                                + ((req.getMessageImprintDigest() != null) ? Base64Util.encode(req
                                                .getMessageImprintDigest()) : "NULL"));
            URL uUrl = new URL(url);
            
            // http authentication
            if (ocspAuthUser != null && ocspAuthPasswd != null) {
                if (LOG.isDebugEnabled()) LOG.debug("OCSP http auth: " + ocspAuthUser + "/" + ocspAuthPasswd);
                HttpAuthenticator auth = new HttpAuthenticator(ocspAuthUser, ocspAuthPasswd);
                Authenticator.setDefault(auth);
            }

            if (LOG.isDebugEnabled()) LOG.debug("Connecting to: " + url);
            URLConnection con = uUrl.openConnection();

            if (LOG.isDebugEnabled()) LOG.debug("Conn opened: " + ((con != null) ? "OK" : "NULL"));
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "application/timestamp-query");
            OutputStream os = con.getOutputStream();

            if (LOG.isDebugEnabled()) LOG.debug("OS: " + ((os != null) ? "OK" : "NULL"));
            os.write(req.getEncoded());
            os.close();

            if (LOG.isDebugEnabled()) LOG.debug("Wrote: " + req.getEncoded().length);

            // read the response
            InputStream is = con.getInputStream();
            int cl = con.getContentLength();
            byte[] bresp = null;
            if (LOG.isDebugEnabled()) LOG.debug("Recv: " + cl + " bytes");
            
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
            if (LOG.isDebugEnabled()) LOG.debug("Received: " + ((bresp != null) ? bresp.length : 0) + " bytes");
            TimeStampResponse resp = new TimeStampResponse(bresp);
            
            if (LOG.isDebugEnabled() && resp.getTimeStampToken() != null
                            && resp.getTimeStampToken().getTimeStampInfo() != null)
                LOG.debug("TS resp: "
                                + resp.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString()
                                + " msg-imprint: "
                                + Base64Util.encode(resp.getTimeStampToken().getTimeStampInfo()
                                                .getMessageImprintDigest()));
            
            return resp;
        } catch (Exception ex) {
            LOG.error("Timestamp getting error: " + ex);
            
        }
        return null;
    }
    
    public TimeStampToken readTsTok(byte[] data) {
        try {
            ASN1InputStream aIn = new ASN1InputStream(data);
            CMSSignedData cmsD = new CMSSignedData(aIn);
            TimeStampToken tstok = new TimeStampToken(cmsD);
            if (LOG.isDebugEnabled() && tstok != null && tstok.getTimeStampInfo() != null)
                LOG.debug("TSTok: " + tstok.getTimeStampInfo().getSerialNumber().toString() + " hash: "
                                + Base64Util.encode(tstok.getTimeStampInfo().getMessageImprintDigest()));
            return tstok;
        } catch (Exception ex) {
            LOG.error("Timestamp getting error: " + ex);
            
        }
        return null;
    }
}
