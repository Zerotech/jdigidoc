package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TimeStampResponse;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.TimestampInfo;
import ee.sk.utils.Base64Util;


public class BouncyCastleTimestampService implements TimestampService {

    private static final Logger LOG = Logger.getLogger(BouncyCastleTimestampService.class);

    /**
     * Verifies this one timestamp
     * @param ts TimestampInfo object
     * @param tsaCert TSA certificate
     * @returns result of verification
     */
    public boolean verifyTimestamp(TimestampInfo ts, X509Certificate tsaCert) throws DigiDocException {
        boolean bOk = false;
        
        if(LOG.isDebugEnabled())
            LOG.debug("Verifying TS: " + ts.getId() + " nr: " + ts.getSerialNumber());     
        if(!SignedDoc.compareDigests(ts.getMessageImprint(), ts.getHash())) {
            LOG.error("TS digest: " + Base64Util.encode(ts.getMessageImprint()) + " real digest: " + Base64Util.encode(ts.getHash()));
            throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                "Bad digest for timestamp: " + ts.getId(), null);
        }
        TimeStampResponse resp = ts.getTimeStampResponse();
        if(resp != null) {
            if(LOG.isDebugEnabled())
                LOG.debug("TS status: " + resp.getStatus());
            if(resp.getStatus() == PKIStatus.GRANTED ||
                resp.getStatus() == PKIStatus.GRANTED_WITH_MODS) {
                try {
                    resp.getTimeStampToken().validate(tsaCert, "BC");
                    bOk = true;
                } catch(Exception ex) {
                    bOk = false;
                    LOG.error("Timestamp verification error: " + ex);
                    throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY, "Invalid timestamp: " + ex.getMessage(), ex);
                }
            }
            else
                throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY, "Invalid timestamp status: " + resp.getStatus(), null);
        }
        
        return bOk;
    }
    
    /**
     * Verifies all timestamps in this signature and
     * return a list of errors.
     * @param sig signature to verify timestamps
     * @return list of errors. Empty if no errors.
     * @throws DigiDocException
     */
    public List<DigiDocException> verifySignaturesTimestamps(Signature sig) {
        Date d1 = null, d2 = null;
        List<DigiDocException> errs = new ArrayList<DigiDocException>();
        List<X509Certificate> tsaCerts = sig.findTSACerts();        
        for(int t = 0; t < sig.countTimestampInfos(); t++)  {
            TimestampInfo ts = sig.getTimestampInfo(t);
            if(ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE)
                d1 = ts.getTime();
            if(ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS)
                d2 = ts.getTime();
            boolean bVerified = false;
            DigiDocException ex2 = null;
            for(int j = 0; j < tsaCerts.size(); j++) {
                X509Certificate tsaCert = (X509Certificate)tsaCerts.get(j);             
                if(LOG.isDebugEnabled())
                    LOG.debug("Verifying TS: " + ts.getId() + " with: " + 
                        SignedDoc.getCommonName(tsaCert.getSubjectDN().getName()));
                // try verifying with all possible TSA certs
                try {
                    if(verifyTimestamp(ts, tsaCert)) {
                        bVerified = true;
                        if(LOG.isDebugEnabled())
                            LOG.debug("TS: " + ts.getId() + " - OK");
                        break;
                    } else {
                        LOG.error("TS: " + ts.getId() + " - NOK");
                    }
                } catch(DigiDocException ex) {
                    ex2 = ex;
                    LOG.error("TS: " + ts.getId() + " - ERROR: " + ex);
                    //ex.printStackTrace(System.err);
                }
            }
            if(!bVerified) {
                errs.add(ex2);
            }
        }
        // now check that SignatureTimeStamp is before SigAndRefsTimeStamp
        if(d1 != null && d2 != null) {
            if(LOG.isDebugEnabled())
                LOG.debug("SignatureTimeStamp: " + d1 + " SigAndRefsTimeStamp: " + d2);
            if(d1.after(d2)) {
                DigiDocException ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY, "SignatureTimeStamp time must be before SigAndRefsTimeStamp time!", null);
                errs.add(ex);
            }
        }
        return errs;
    }

}
