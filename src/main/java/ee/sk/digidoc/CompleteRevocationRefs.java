/*
 * CompleteRevocationRefs.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
 * AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */

package ee.sk.digidoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;

/**
 * Models the ETSI CompleteRevocationRefs element This contains some data from
 * the OCSP response and it's digest
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class CompleteRevocationRefs implements Serializable {
    /** <OCSPIdentifier> URI attribute */
    private String uri;

    private String responderId;

    private Date producedAt;

    private String digestAlgorithm;

    private byte[] digestValue;
    /** parent object - UnsignedProperties ref */
    private UnsignedProperties unsignedProps;

    
    public CompleteRevocationRefs() {
    }

    /**
     * Creates new CompleteRevocationRefs
     * 
     * @param uri
     *            notary uri value
     * @param respId
     *            responder id
     * @param producedAt
     *            OCSP producedAt timestamp
     * @param digAlg
     *            notary digest algorithm
     * @param digest
     *            notary digest
     * @throws DigiDocException
     *             for validation errors
     */
    public CompleteRevocationRefs(String uri, String respId, Date producedAt, String digAlg, byte[] digest)
            throws DigiDocException {
        setUri(uri);
        setResponderId(respId);
        setProducedAt(producedAt);
        setDigestAlgorithm(digAlg);
        setDigestValue(digest);
    }

    /**
     * Creates new CompleteRevocationRefs by using data from an existing Notary
     * object
     * 
     * @param not
     *            Notary object
     * @throws DigiDocException
     *             for validation errors
     */
    public CompleteRevocationRefs(Notary not) throws DigiDocException {
        setUri("#" + not.getId());
        setResponderId(not.getResponderId());
        setProducedAt(not.getProducedAt());
        setDigestAlgorithm(SignedDoc.SHA1_DIGEST_ALGORITHM);
        byte[] digest = null;
        try {
            byte[] ocspData = not.getOcspResponseData();
            digest = DDUtils.digest(ocspData);
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        setDigestValue(digest);
    }

    public UnsignedProperties getUnsignedProperties() {
        return unsignedProps;
    }

    public void setUnsignedProperties(UnsignedProperties uprops) {
        unsignedProps = uprops;
    }

    public String getUri() {
        return uri;
    }

    /**
     * Mutator for uri attribute
     * 
     * @param str
     *            new value for uri attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setUri(String str) throws DigiDocException {
        DigiDocException ex = validateUri(str);
        if (ex != null)
            throw ex;
        uri = str;
    }

    /**
     * Helper method to validate an uri
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateUri(String str) {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_URI, "Notary uri must be in form: #<notary-id>",
                    null);
        return ex;
    }

    public String getResponderId() {
        return responderId;
    }

    /**
     * Mutator for responderId attribute
     * 
     * @param str
     *            new value for responderId attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setResponderId(String str) throws DigiDocException {
        DigiDocException ex = validateResponderId(str);
        
        if (ex != null) {
            throw ex;
        }
            
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
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateResponderId(String str) {
        DigiDocException ex = null;
        
        if (str == null) {
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_RESP_ID, "ResponderId cannot be empty!", null);
        }
            
        return ex;
    }

    public Date getProducedAt() {
        return producedAt;
    }

    /**
     * Mutator for producedAt attribute
     * 
     * @param str
     *            new value for producedAt attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setProducedAt(Date d) throws DigiDocException {
        DigiDocException ex = validateProducedAt(d);
        
        if (ex != null) {
            throw ex;
        }
            
        producedAt = d;
    }

    /**
     * Helper method to validate producedAt timestamp
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateProducedAt(Date d) {
        DigiDocException ex = null;
        
        if (d == null) {
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_PRODUCED_AT,
                    "ProducedAt timestamp cannot be empty!", null);
        }
            
        return ex;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Mutator for digestAlgorithm attribute
     * 
     * @param str
     *            new value for digestAlgorithm attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setDigestAlgorithm(String str) throws DigiDocException {
        DigiDocException ex = validateDigestAlgorithm(str);
        
        if (ex != null) {
            throw ex;
        }
            
        digestAlgorithm = str;
    }

    /**
     * Helper method to validate a digest algorithm
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestAlgorithm(String str) {
        DigiDocException ex = null;

        if (str == null || !str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM)) {
            ex = new DigiDocException(DigiDocException.ERR_CERT_DIGEST_ALGORITHM,
                    "Currently supports only SHA1 digest algorithm", null);
        }

        return ex;
    }

    public byte[] getDigestValue() {
        return digestValue;
    }

    /**
     * Mutator for digestValue attribute
     * 
     * @param data
     *            new value for digestValue attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setDigestValue(byte[] data) throws DigiDocException {
        DigiDocException ex = validateDigestValue(data);

        if (ex != null) {
            throw ex;
        }

        digestValue = data;
    }

    /**
     * Helper method to validate a digest value
     * 
     * @param data
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestValue(byte[] data) {
        DigiDocException ex = null;

        if (data == null || data.length != SignedDoc.SHA1_DIGEST_LENGTH) {
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH,
                    "SHA1 digest data is allways 20 bytes of length", null);
        }

        return ex;
    }

    /**
     * Helper method to validate the whole CompleteRevocationRefs object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate() {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = validateUri(uri);
        if (ex != null)
            errs.add(ex);
        ex = validateResponderId(responderId);
        if (ex != null)
            errs.add(ex);
        ex = validateProducedAt(producedAt);
        if (ex != null)
            errs.add(ex);
        ex = validateDigestAlgorithm(digestAlgorithm);
        if (ex != null)
            errs.add(ex);
        ex = validateDigestValue(digestValue);
        if (ex != null)
            errs.add(ex);
        return errs;
    }

    /**
     * Converts the CompleteRevocationRefs to XML form
     * 
     * @return XML representation of CompleteRevocationRefs
     */
    public byte[] toXML() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(ConvertUtils.str2data("<CompleteRevocationRefs>\n"));
            bos.write(ConvertUtils.str2data("<OCSPRefs>\n<OCSPRef>\n"));
            bos.write(ConvertUtils.str2data("<OCSPIdentifier URI=\""));
            bos.write(ConvertUtils.str2data(uri));
            bos.write(ConvertUtils.str2data("\">\n<ResponderID>"));

            if (unsignedProps.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                bos.write(ConvertUtils.str2data("<ByName>\n"));
                if (responderId.indexOf("byName: ") != -1) {
                    responderId = responderId.replace("byName: ", "");
                }
                if (responderId.indexOf("E=") != -1) {
                    responderId = responderId.replace("E=", "emailAddress=");
                }
                bos.write(ConvertUtils.str2data(responderId));
                bos.write(ConvertUtils.str2data("</ByName>"));
            } else {
                bos.write(ConvertUtils.str2data(responderId));
            }

            bos.write(ConvertUtils.str2data("</ResponderID>\n<ProducedAt>"));
            bos.write(ConvertUtils.str2data(ConvertUtils.date2string(producedAt, unsignedProps.getSignature().getSignedDoc())));
            bos.write(ConvertUtils.str2data("</ProducedAt>\n</OCSPIdentifier>\n<DigestAlgAndValue>\n<DigestMethod Algorithm=\""));
            bos.write(ConvertUtils.str2data(digestAlgorithm));
            bos.write(ConvertUtils.str2data("\" xmlns=\""));
            bos.write(ConvertUtils.str2data(SignedDoc.XMLNS_XMLDSIG));
            bos.write(ConvertUtils.str2data("\"></DigestMethod>\n<DigestValue xmlns=\""));
            bos.write(ConvertUtils.str2data(SignedDoc.XMLNS_XMLDSIG));
            bos.write(ConvertUtils.str2data("\">"));
            bos.write(ConvertUtils.str2data(Base64Util.encode(digestValue, 0)));
            bos.write(ConvertUtils.str2data("</DigestValue>\n</DigestAlgAndValue>"));
            bos.write(ConvertUtils.str2data("</OCSPRef>\n</OCSPRefs>\n"));
            bos.write(ConvertUtils.str2data("</CompleteRevocationRefs>"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        
        return bos.toByteArray();
    }

    @Override
    public String toString() {
        return new String(toXML());
    }
}
