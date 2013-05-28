package ee.sk.digidoc;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class OcspRef implements Serializable {
    
    /** <OCSPIdentifier> URI attribute */
    private String uri;
    /** <ResponderId> element */
    private String responderId;
    /** ProducedAt element */
    private Date producedAt;
    /** digest algorithm uri/id */
    private String digestAlgorithm;
    /** digest value */
    private byte[] digestValue;
    
    public OcspRef() {}
    
    /**
     * Creates new OcspRef
     * 
     * @param uri notary uri value
     * @param respId responder id
     * @param producedAt OCSP producedAt timestamp
     * @param digAlg notary digest algorithm
     * @param digest notary digest
     * @throws DigiDocException for validation errors
     */
    public OcspRef(String uri, String respId, Date producedAt, String digAlg, byte[] digest) throws DigiDocException {
        setUri(uri);
        setResponderId(respId);
        setProducedAt(producedAt);
        setDigestAlgorithm(digAlg);
        setDigestValue(digest);
    }
    
    /**
     * Accessor for uri attribute
     * 
     * @return value of uri attribute
     */
    public String getUri() {
        return uri;
    }
    
    /**
     * Mutator for uri attribute
     * 
     * @param str new value for uri attribute
     * @throws DigiDocException for validation errors
     */
    public void setUri(String str) throws DigiDocException {
        DigiDocException ex = validateUri(str);
        if (ex != null) throw ex;
        uri = str;
    }
    
    /**
     * Helper method to validate an uri
     * 
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateUri(String str) {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_URI, "OCSP ref uri must be in form: #<ref-id>", null);
        return ex;
    }
    
    /**
     * Accessor for responderId attribute
     * 
     * @return value of responderId attribute
     */
    public String getResponderId() {
        return responderId;
    }
    
    /**
     * Mutator for responderId attribute
     * 
     * @param str new value for responderId attribute
     * @throws DigiDocException for validation errors
     */
    public void setResponderId(String str) throws DigiDocException {
        DigiDocException ex = validateResponderId(str);
        if (ex != null) throw ex;
        responderId = str;
    }
    
    /**
     * Returns reponder-ids CN
     * 
     * @returns reponder-ids CN or null
     */
    public String getResponderCommonName() {
        String name = null;
        if (responderId != null) {
            int idx1 = responderId.indexOf("CN=");
            if (idx1 != -1) {
                idx1 += 2;
                while (idx1 < responderId.length() && !Character.isLetter(responderId.charAt(idx1)))
                    idx1++;
                int idx2 = idx1;
                while (idx2 < responderId.length() && responderId.charAt(idx2) != ','
                                && responderId.charAt(idx2) != '/')
                    idx2++;
                name = responderId.substring(idx1, idx2);
            }
        }
        return name;
    }
    
    /**
     * Helper method to validate a ResponderId
     * 
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateResponderId(String str) {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_RESP_ID, "ResponderId cannot be empty!", null);
        return ex;
    }
    
    /**
     * Accessor for producedAt attribute
     * 
     * @return value of producedAt attribute
     */
    public Date getProducedAt() {
        return producedAt;
    }
    
    /**
     * Mutator for producedAt attribute
     * 
     * @param str new value for producedAt attribute
     * @throws DigiDocException for validation errors
     */
    public void setProducedAt(Date d) throws DigiDocException {
        DigiDocException ex = validateProducedAt(d);
        if (ex != null) throw ex;
        producedAt = d;
    }
    
    /**
     * Helper method to validate producedAt timestamp
     * 
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateProducedAt(Date d) {
        DigiDocException ex = null;
        if (d == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_PRODUCED_AT,
                            "ProducedAt timestamp cannot be empty!", null);
        return ex;
    }
    
    /**
     * Accessor for digestAlgorithm attribute
     * 
     * @return value of digestAlgorithm attribute
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }
    
    /**
     * Mutator for digestAlgorithm attribute
     * 
     * @param str new value for digestAlgorithm attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigestAlgorithm(String str) throws DigiDocException {
        DigiDocException ex = validateDigestAlgorithm(str);
        if (ex != null) throw ex;
        digestAlgorithm = str;
    }
    
    /**
     * Helper method to validate a digest algorithm
     * 
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestAlgorithm(String str) {
        DigiDocException ex = null;
        if (str == null
                        || (!str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM)
                                        && !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1)
                                        && !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_2) && !str
                                            .equals(SignedDoc.SHA512_DIGEST_ALGORITHM)))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM,
                            "Currently supports only SHA1, SHA256 or SHA256 digest algorithm", null);
        return ex;
    }
    
    /**
     * Accessor for digestValue attribute
     * 
     * @return value of digestValue attribute
     */
    public byte[] getDigestValue() {
        return digestValue;
    }
    
    /**
     * Mutator for digestValue attribute
     * 
     * @param data new value for digestValue attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigestValue(byte[] data) throws DigiDocException {
        DigiDocException ex = validateDigestValue(data);
        if (ex != null) throw ex;
        digestValue = data;
    }
    
    /**
     * Helper method to validate a digest value
     * 
     * @param data input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestValue(byte[] data) {
        DigiDocException ex = null;
        if (data == null
                        || (data.length != SignedDoc.SHA1_DIGEST_LENGTH
                                        && data.length != SignedDoc.SHA256_DIGEST_LENGTH && data.length != SignedDoc.SHA512_DIGEST_LENGTH))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH, "Invalid digest length", null);
        return ex;
    }
    
    /**
     * Helper method to validate the whole
     * CompleteRevocationRefs object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate() {
        List<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = validateUri(uri);
        if (ex != null) errs.add(ex);
        ex = validateResponderId(responderId);
        if (ex != null) errs.add(ex);
        ex = validateProducedAt(producedAt);
        if (ex != null) errs.add(ex);
        ex = validateDigestAlgorithm(digestAlgorithm);
        if (ex != null) errs.add(ex);
        ex = validateDigestValue(digestValue);
        if (ex != null) errs.add(ex);
        return errs;
    }
}
