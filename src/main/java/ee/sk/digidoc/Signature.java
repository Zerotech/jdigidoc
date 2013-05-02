/*
 * Signature.java
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
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import ee.sk.digidoc.services.CanonicalizationService;
import ee.sk.digidoc.services.DigiDocGenServiceImpl;
import ee.sk.digidoc.services.DigiDocXmlGenerator;
import ee.sk.utils.DDUtils;

/**
 * Models an XML-DSIG/ETSI Signature. A signature can contain references
 * SignedInfo (truly signed data) and signed and unsigned properties.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class Signature implements Serializable {
    
    private static Logger LOG = Logger.getLogger(Signature.class);
    /** reference to the parent SignedDoc object */
    private SignedDoc signedDoc;

    private String id;

    private SignedInfo signedInfo;

    private SignatureValue signatureValue;

    private KeyInfo keyInfo;

    private SignedProperties signedProperties;

    private QualifyingProperties qualifyingProperties;

    private UnsignedProperties unsignedProperties;
    /** original bytes read from XML file */
    private byte[] origContent;
    /** CertID elements */
    private List<CertID> certIds;
    /** CertValue elements */
    private List<CertValue> certValues;
    /** TimestampInfo elements */
    private List<TimestampInfo> timestamps;
    /** cached list of errors */
    private List<DigiDocException> errors;
    
    private String httpFrom;
    /** path in bdoc container */
    private String path;
    
    private String profile;

    public Signature(SignedDoc sigDoc) {
        signedDoc = sigDoc;
    }

    public SignedDoc getSignedDoc() {
        return signedDoc;
    }

    public void setSignedDoc(SignedDoc sigDoc) {
        signedDoc = sigDoc;
    }

    public String getId() {
        return id;
    }

    /**
     * Mutator for id attribute
     * 
     * @param str
     *            new value for id attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setId(String str) throws DigiDocException {
        DigiDocException ex = validateId(str);
        if (ex != null) throw ex;
        id = str;
    }

    public byte[] getOrigContent() {
        return origContent;
    }

    public void setOrigContent(byte[] data) {
        origContent = data;
    }

    /**
     * Helper method to validate an id
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    public DigiDocException validateId(String str) {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_SIGNATURE_ID, "Id is a required attribute", null);
        return ex;
    }

    public SignedInfo getSignedInfo() {
        return signedInfo;
    }

    public void setSignedInfo(SignedInfo si) {
        signedInfo = si;
    }

    /**
     * Calculates the SignedInfo digest
     * 
     * @return SignedInfo digest
     */
    public byte[] calculateSignedInfoDigest(CanonicalizationService canonicalizationService) throws DigiDocException {
        return DDUtils.calculateDigest(signedInfo, canonicalizationService);
    }
    
    /**
     * Calculates the SignedInfo xml to sign
     * 
     * @return SignedInfo xml
     * @throws DigiDocException
     */
    public byte[] calculateSignedInfoXML() throws DigiDocException {
        DigiDocXmlGenerator xmlGenerator = new DigiDocXmlGenerator(signedDoc);
        return xmlGenerator.signedInfoToXML(this, signedInfo);
    }
    
    /**
     * Returns HTTP_FROM value. This value is used
     * as a http header during ocsp requests. It must be
     * set before calling DigiDocGenFactory.finalizeSignature()
     * 
     * @return HTTP_FROM value
     */
    public String getHttpFrom() {
        return this.httpFrom;
    }
    
    /**
     * Sets HTTP_FROM value. This value is used
     * as a http header during ocsp requests. It must be
     * set before calling DigiDocGenFactory.finalizeSignature()
     * 
     * @param s HTTP_FROM value
     */
    public void setHttpFrom(String s) {
        this.httpFrom = s;
    }

    public SignatureValue getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(SignatureValue sv) {
        signatureValue = sv;
        origContent = null;
    }

    /**
     * Creates a new SignatureValue object of this signature
     * 
     * @param sigv
     *            signatures byte data
     * @throws DigiDocException
     *             for validation errors
     */
    public void setSignatureValue(byte[] sigv) throws DigiDocException {
        SignatureValue sv = new SignatureValue(this, sigv);
        setSignatureValue(sv);
    }

    public KeyInfo getKeyInfo() {
        return keyInfo;
    }

    public void setKeyInfo(KeyInfo ki) {
        keyInfo = ki;
    }

    public SignedProperties getSignedProperties() {
        return signedProperties;
    }

    public void setSignedProperties(SignedProperties sp) {
        signedProperties = sp;
    }

    public UnsignedProperties getUnsignedProperties() {
        return unsignedProperties;
    }

    public void setUnsignedProperties(UnsignedProperties usp) {
        unsignedProperties = usp;
    }

    /**
     * return the count of CertID objects
     * 
     * @return count of CertID objects
     */
    public int countCertIDs() {
        return ((certIds == null) ? 0 : certIds.size());
    }

    /**
     * Adds a new CertID object
     * 
     * @param cid
     *            new object to be added
     */
    public void addCertID(CertID cid) {
        if (certIds == null) {
            certIds = new ArrayList<CertID>();
        }
        cid.setSignature(this);
        certIds.add(cid);
    }

    /**
     * Retrieves CertID element with the desired index
     * 
     * @param idx
     *            CertID index
     * @return CertID element or null if not found
     */
    public CertID getCertID(int idx) {
        if (certIds != null && idx < certIds.size()) {
            return certIds.get(idx);
        }
        return null; // not found
    }

    /**
     * Retrieves the last CertID element
     * 
     * @return CertID element or null if not found
     */
    public CertID getLastCertId() {
        if (certIds != null && certIds.size() > 0) {
            return certIds.get(certIds.size() - 1);
        }
        return null; // not found
    }

    /**
     * Retrieves CertID element with the desired type
     * 
     * @param type
     *            CertID type
     * @return CertID element or null if not found
     */
    public CertID getCertIdOfType(int type) {
        for (int i = 0; (certIds != null) && (i < certIds.size()); i++) {
            CertID cid = certIds.get(i);
            if (cid.getType() == type) {
                return cid;
            }
        }
        return null; // not found
    }

    /**
     * Retrieves CertID element with the desired type. If not found creates a
     * new one with this type.
     * 
     * @param type
     *            CertID type
     * @return CertID element
     * @throws DigiDocException
     *             for validation errors
     */
    public CertID getOrCreateCertIdOfType(int type) throws DigiDocException {
        CertID cid = getCertIdOfType(type);
        if (cid == null) {
            cid = new CertID();
            cid.setType(type);
            addCertID(cid);
        }
        return cid; // not found
    }

    /**
     * return the count of CertValue objects
     * 
     * @return count of CertValues objects
     */
    public int countCertValues() {
        return ((certValues == null) ? 0 : certValues.size());
    }

    /**
     * Adds a new CertValue object
     * 
     * @param cval
     *            new object to be addedsetid
     */
    public void addCertValue(CertValue cval) {
        if (certValues == null) {
            certValues = new ArrayList<CertValue>();
        }
        cval.setSignature(this);
        certValues.add(cval);
    }

    /**
     * Retrieves CertValue element with the desired index
     * 
     * @param idx
     *            CertValue index
     * @return CertValue element or null if not found
     */
    public CertValue getCertValue(int idx) {
        if (certValues != null && idx < certValues.size()) {
            return certValues.get(idx);
        } else
            return null; // not found
    }

    /**
     * Retrieves the last CertValue element
     * 
     * @return CertValue element or null if not found
     */
    public CertValue getLastCertValue() {
        if (certValues != null && certValues.size() > 0) {
            return certValues.get(certValues.size() - 1);
        } else
            return null; // not found
    }

    /**
     * Retrieves CertValue element with the desired type
     * 
     * @param type
     *            CertValue type
     * @return CertValue element or null if not found
     */
    public CertValue getCertValueOfType(int type) {
        for (int i = 0; (certValues != null) && (i < certValues.size()); i++) {
            CertValue cval = certValues.get(i);
            if (cval.getType() == type) {
                return cval;
            }
        }
        return null; // not found
    }

    /**
     * Retrieves CertValue element with the desired type. If not found creates a
     * new one with this type.
     * 
     * @param type
     *            CertValue type
     * @return CertValue element
     * @throws DigiDocException
     *             for validation errors
     */
    public CertValue getOrCreateCertValueOfType(int type) throws DigiDocException {
        CertValue cval = getCertValueOfType(type);
        if (cval == null) {
            cval = new CertValue();
            cval.setType(type);
            addCertValue(cval);
        }
        return cval; // not found
    }

    /**
     * Returns the first CertValue with the given serial number that has been
     * attached to this signature in digidoc document. This could be either the
     * signers cert, OCSP responders cert or one of the TSA certs.
     * 
     * @param serNo
     *            certificates serial number
     * @return found CertValue or null
     */
    public CertValue findCertValueWithSerial(BigInteger serNo) {
        for (int i = 0; (certValues != null) && (i < certValues.size()); i++) {
            CertValue cval = certValues.get(i);
            if (cval.getCert().getSerialNumber().equals(serNo)) {
                return cval;
            }
        }
        return null;
    }

    /**
     * Retrieves OCSP respoinders certificate
     * 
     * @return OCSP respoinders certificate
     */
    public X509Certificate findResponderCert() {
        CertValue cval = getCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
        if (cval != null)
            return cval.getCert();
        else
            return null;
    }

    /**
     * Retrieves TSA certificates
     * 
     * @return TSA certificates
     */
    public List<X509Certificate> findTSACerts() {
        ArrayList<X509Certificate> vec = new ArrayList<X509Certificate>();
        for (int i = 0; (certValues != null) && (i < certValues.size()); i++) {
            CertValue cval = certValues.get(i);
            if (cval.getType() == CertValue.CERTVAL_TYPE_TSA) {
                vec.add(cval.getCert());
            }
        }
        return vec;
    }

    /**
     * return the count of TimestampInfo objects
     * 
     * @return count of TimestampInfo objects
     */
    public int countTimestampInfos() {
        return ((timestamps == null) ? 0 : timestamps.size());
    }

    /**
     * Adds a new TimestampInfo object
     * 
     * @param ts
     *            new object to be added
     */
    public void addTimestampInfo(TimestampInfo ts) {
        if (timestamps == null) {
            timestamps = new ArrayList<TimestampInfo>();
        }
        ts.setSignature(this);
        timestamps.add(ts);
    }

    /**
     * Retrieves TimestampInfo element with the desired index
     * 
     * @param idx
     *            TimestampInfo index
     * @return TimestampInfo element or null if not found
     */
    public TimestampInfo getTimestampInfo(int idx) {
        if (timestamps != null && idx < timestamps.size()) {
            return timestamps.get(idx);
        } else
            return null; // not found
    }

    /**
     * Retrieves the last TimestampInfo element
     * 
     * @return TimestampInfo element or null if not found
     */
    public TimestampInfo getLastTimestampInfo() {
        if (timestamps != null && timestamps.size() > 0) {
            return timestamps.get(timestamps.size() - 1);
        } else
            return null; // not found
    }

    /**
     * Retrieves TimestampInfo element with the desired type
     * 
     * @param type
     *            TimestampInfo type
     * @return TimestampInfo element or null if not found
     */
    public TimestampInfo getTimestampInfoOfType(int type) {
        for (int i = 0; (timestamps != null) && (i < timestamps.size()); i++) {
            TimestampInfo ts = timestamps.get(i);
            if (ts.getType() == type) {
                return ts;
            }
        }
        return null; // not found
    }

    /**
     * Retrieves TimestampInfo element with the desired type. If not found
     * creates a new one with this type.
     * 
     * @param type
     *            TimestampInfo type
     * @return TimestampInfo element
     * @throws DigiDocException
     *             for validation errors
     */
    public TimestampInfo getOrCreateTimestampInfoOfType(int type) throws DigiDocException {
        TimestampInfo ts = getTimestampInfoOfType(type);
        if (ts == null) {
            ts = new TimestampInfo();
            ts.setType(type);
            addTimestampInfo(ts);
        }
        return ts; // not found
    }
    
    /**
     * Accessor for path attribute
     * 
     * @return value of path attribute
     */
    public String getPath() {
        return path;
    }
    
    /**
     * Mutator for path attribute
     * 
     * @param s new value for path attribute
     */
    public void setPath(String s) {
        path = s;
    }
    
    /**
     * Accessor for profile attribute
     * 
     * @return value of profile attribute
     */
    public String getProfile() {
        return profile;
    }
    
    /**
     * Mutator for profile attribute
     * 
     * @param s new value for profile attribute
     */
    public void setProfile(String s) {
        profile = s;
    }

    /**
     * Gets confirmation and adds the corresponding members that carry the
     * returned info to this signature
     * 
     * @throws DigiDocException
     *             for all errors
     */
    public void getConfirmation(DigiDocGenServiceImpl genService) throws DigiDocException {
        if (signedDoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)
                        || signedDoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
            if (profile == null || profile.equalsIgnoreCase(SignedDoc.BDOC_PROFILE_TM)) {
                genService.finalizeXadesT(signedDoc, this);
                genService.finalizeXadesC(signedDoc, this);
                genService.finalizeXadesXL_TM(signedDoc, this);
            }
        } else {
            String profile = this.profile;
            if (profile == null) profile = signedDoc.getProfile();
            if (profile == null || profile.trim().length() == 0) profile = SignedDoc.BDOC_PROFILE_TM;
            genService.finalizeSignature(signedDoc, this, signatureValue.getValue(), profile);
        }
        // reset original content since we just added to confirmation
        if (origContent != null) {
            DigiDocXmlGenerator xmlGenerator = new DigiDocXmlGenerator(signedDoc);
            String str = new String(origContent);
            int idx1 = str.indexOf("</SignedProperties>");
            if (idx1 != -1) {
                try {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    bos.write(origContent, 0, idx1);
                    bos.write("</SignedProperties>".getBytes());
                    bos.write(xmlGenerator.unsignedPropertiesToXML(this, unsignedProperties));
                    bos.write("</QualifyingProperties></Object></Signature>".getBytes());
                    origContent = bos.toByteArray();
                } catch (java.io.IOException ex) {
                    DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
                }
            }
        }
    }
    
    public QualifyingProperties getQualifyingProperties() {
        return qualifyingProperties;
    }

    public void setQualifyingProperties(QualifyingProperties prop) {
        qualifyingProperties = prop;
    }

    public List<TimestampInfo> getTimestamps() {
        return timestamps;
    }
    
    /**
     * Accessor for signedInfo attribute
     * 
     * @return value of signedInfo attribute
     */
    public String getSubject() {
        return keyInfo.getSubjectFirstName() + " " + keyInfo.getSubjectLastName() + " "
                        + keyInfo.getSubjectPersonalCode();
    }
    
    public List<DigiDocException> getErrors() {
        return errors;
    }
    
    public void setErrors(List<DigiDocException> errs) {
        errors = errs;
    }
    
    public String getStatus() {
        if (errors == null || errors.size() == 0) {
            if (signatureValue != null && signatureValue.getValue() != null)
                return "OK";
            else
                return "INCOMPLETE";
        } else
            return "ERROR";
    }
    
    /**
     * Converts Signature object to String representation
     * mainly for debugging purposes
     */
    public String toString() {
        try {
            DigiDocXmlGenerator xmlGenerator = new DigiDocXmlGenerator(signedDoc);
            return new String(xmlGenerator.signatureToXML(this), "UTF-8");
        } catch (Exception ex) {
            LOG.error("Error converting Signature to string: " + ex);
        }
        return null;
    }
}
