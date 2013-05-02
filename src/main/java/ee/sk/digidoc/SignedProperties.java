/*
 * SignedProperties.java
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

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import ee.sk.utils.DDUtils;

/**
 * Models the SignedProperties element of an XML-DSIG/ETSI Signature.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class SignedProperties implements Serializable {
    /** signature object to which this belongs */
    private Signature m_sig;

    private String m_id;

    private String m_target;
    /** signing time measured by signers own computer */
    private Date m_signingTime;
    /** signers certs digest algorithm */
    private String m_certDigestAlgorithm;
    /** signers cert id */
    private String m_certId;
    /** signers certs digest data */
    private byte[] m_certDigestValue;
    /** signers certs issuer serial number */
    private BigInteger m_certSerial;
    /** signature production place */
    private SignatureProductionPlace m_address;
    /** claimed roles */
    private List<String> m_claimedRoles;
    /** digest over the original bytes read from XML file */
    private byte[] m_origDigest;
    /** SignedDataObjectProperties */
    private String m_SignedDataObjectProperties;
    /** DataObjectFormat */
    private String m_DataObjectFormat;
    
    /**
     * Creates new SignedProperties. Initializes everything to null
     * 
     * @param sig
     *            parent signature
     */
    public SignedProperties(Signature sig) {
        m_sig = sig;
        m_id = null;
        m_target = null;
        m_signingTime = null;
        m_certDigestAlgorithm = null;
        m_certDigestValue = null;
        m_certSerial = null;
        m_claimedRoles = null;
        m_address = null;
        m_certId = null;
        m_origDigest = null;
    }

    /**
     * Creates new SignedProperties.
     * 
     * @param sig
     *            parent signature
     * @param id
     *            id attribute value
     * @param target
     *            target attribute value
     * @param signingTime
     *            signing timestamp
     * @param certId
     *            signers cert id (in XML)
     * @param certDigAlg
     *            signers cert digest algorithm id/uri
     * @param digest
     *            signers cert digest value
     * @param serial
     *            signers cert serial number
     * @throws DigiDocException
     *             for validation errors
     */
    public SignedProperties(Signature sig, String id, String target, Date signingTime, String certId,
                    String certDigAlg, byte[] digest, BigInteger serial) throws DigiDocException {
        m_sig = sig;
        setId(id);
        setTarget(target);
        setSigningTime(signingTime);
        setCertId(certId);
        setCertDigestAlgorithm(certDigAlg);
        setCertDigestValue(digest);
        setCertSerial(serial);
        m_claimedRoles = null;
        m_address = null;
        m_origDigest = null;
    }

    /**
     * Creates new SignedProperties with default values taken from signers
     * certificate and signature
     * 
     * @param sig
     *            Signature reference
     * @param cert
     *            signers certificate
     * @param claimedRoles
     *            signers claimed roles
     * @param adr
     *            signers address
     * @throws DigiDocException
     *             for validation errors
     */
    public SignedProperties(Signature sig, X509Certificate cert, String[] claimedRoles, SignatureProductionPlace adr)
                    throws DigiDocException {
        m_sig = sig;
        setId(sig.getId() + "-SignedProperties");
        setTarget("#" + sig.getId());
        setSigningTime(new Date());
        setCertId(sig.getId() + "-CERTINFO");
        try {
            String sDigType = DDUtils.getDefaultDigestType(sig.getSignedDoc());
            String sDigAlg = DDUtils.digType2Alg(sDigType);
            setCertDigestAlgorithm(sDigAlg);
            setCertDigestValue(DDUtils.digestOfType(cert.getEncoded(), sDigType));
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        setCertSerial(cert.getSerialNumber());
        if ((claimedRoles != null) && (claimedRoles.length > 0)) {
            for (int i = 0; i < claimedRoles.length; i++)
                addClaimedRole(claimedRoles[i]);
        }
        if (adr != null) setSignatureProductionPlace(adr);
        m_origDigest = null;
    }

    /**
     * Accessor for id attribute
     * 
     * @return value of id attribute
     */
    public String getId() {
        return m_id;
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
        m_id = str;
    }

    /**
     * Accessor for origDigest attribute
     * 
     * @return value of origDigest attribute
     */
    public byte[] getOrigDigest() {
        return m_origDigest;
    }

    /**
     * Mutator for origDigest attribute
     * 
     * @param str
     *            new value for origDigest attribute
     */
    public void setOrigDigest(byte[] data) {
        m_origDigest = data;
    }

    /**
     * Helper method to validate an id
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str) {
        DigiDocException ex = null;
        if (str == null) ex = new DigiDocException(DigiDocException.ERR_SIGPROP_ID, "Id must not be empty", null);
        return ex;
    }

    /**
     * Accessor for target attribute
     * 
     * @return value of target attribute
     */
    public String getTarget() {
        return m_target;
    }

    /**
     * Mutator for target attribute
     * 
     * @param str
     *            new value for target attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setTarget(String str) throws DigiDocException {
        DigiDocException ex = validateTarget(str);
        if (ex != null) throw ex;
        m_target = str;
    }

    /**
     * Helper method to validate a target
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateTarget(String str) {
        DigiDocException ex = null;
        if (str == null && m_sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)
                        && !m_sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)) {
            ex = new DigiDocException(DigiDocException.ERR_SIGPROP_TARGET, "Target must be in form: #<signature-id>",
                            null);
        }

        return ex;
    }

    /**
     * Accessor for certId attribute
     * 
     * @return value of certId attribute
     */
    public String getCertId() {
        return m_certId;
    }

    /**
     * Mutator for certId attribute
     * 
     * @param str
     *            new value for certId attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setCertId(String str) throws DigiDocException {
        if (m_sig.getSignedDoc() != null && !m_sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                        && !m_sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)) {
            DigiDocException ex = validateCertId(str);
            if (ex != null) throw ex;
        }
        m_certId = str;
    }

    /**
     * Helper method to validate an certificate id
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateCertId(String str) {
        DigiDocException ex = null;
        if (str == null && !m_sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            ex = new DigiDocException(DigiDocException.ERR_SIGPROP_CERT_ID,
                            "Cert Id must be in form: <signature-id>-CERTINFO", null);
        }
        return ex;
    }

    /**
     * Accessor for signatureProductionPlace attribute
     * 
     * @return value of signatureProductionPlace attribute
     */
    public SignatureProductionPlace getSignatureProductionPlace() {
        return m_address;
    }

    /**
     * Mutator for signatureProductionPlace attribute
     * 
     * @param str
     *            new value for signatureProductionPlace attribute
     */
    public void setSignatureProductionPlace(SignatureProductionPlace adr) throws DigiDocException {
        m_address = adr;
    }

    /**
     * Accessor for signingTime attribute
     * 
     * @return value of signingTime attribute
     */
    public Date getSigningTime() {
        return m_signingTime;
    }

    /**
     * Mutator for signingTime attribute
     * 
     * @param str
     *            new value for signingTime attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setSigningTime(Date d) throws DigiDocException {
        DigiDocException ex = validateSigningTime(d);
        if (ex != null) throw ex;
        m_signingTime = d;
    }

    /**
     * Helper method to validate a signingTime
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateSigningTime(Date d) {
        DigiDocException ex = null;
        if (d == null) // check the uri somehow ???
            ex = new DigiDocException(DigiDocException.ERR_SIGNING_TIME, "Singing time cannot be empty!", null);
        return ex;
    }

    /**
     * Accessor for certDigestAlgorithm attribute
     * 
     * @return value of certDigestAlgorithm attribute
     */
    public String getCertDigestAlgorithm() {
        return m_certDigestAlgorithm;
    }

    /**
     * Mutator for certDigestAlgorithm attribute
     * 
     * @param str
     *            new value for certDigestAlgorithm attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setCertDigestAlgorithm(String str) throws DigiDocException {
        DigiDocException ex = validateCertDigestAlgorithm(str);
        if (ex != null) throw ex;
        m_certDigestAlgorithm = str;
    }

    /**
     * Helper method to validate a digest algorithm
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateCertDigestAlgorithm(String str) {
        DigiDocException ex = null;
        if (str == null
                        || (!str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM)
                                        && !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1)
                                        && !str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_2) && !str
                                            .equals(SignedDoc.SHA512_DIGEST_ALGORITHM))) {
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM,
                            "Currently supports only SHA1, SHA256 or SHA256 digest algorithm", null);
        }
        return ex;
    }

    /**
     * Accessor for certDigestValue attribute
     * 
     * @return value of certDigestValue attribute
     */
    public byte[] getCertDigestValue() {
        return m_certDigestValue;
    }

    /**
     * Mutator for certDigestValue attribute
     * 
     * @param data
     *            new value for certDigestValue attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setCertDigestValue(byte[] data) throws DigiDocException {
        DigiDocException ex = validateCertDigestValue(data);
        if (ex != null) throw ex;
        m_certDigestValue = data;
    }

    /**
     * Helper method to validate a digest value
     * 
     * @param data
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateCertDigestValue(byte[] data) {
        DigiDocException ex = null;
        if (data == null
                        || (data.length != SignedDoc.SHA1_DIGEST_LENGTH
                                        && data.length != SignedDoc.SHA256_DIGEST_LENGTH && data.length != SignedDoc.SHA512_DIGEST_LENGTH)) {
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH, "Invalid digest length", null);
        }
        return ex;
    }

    /**
     * Accessor for certSerial attribute
     * 
     * @return value of certSerial attribute
     */
    public BigInteger getCertSerial() {
        return m_certSerial;
    }

    /**
     * Mutator for certSerial attribute
     * 
     * @param str
     *            new value for certSerial attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setCertSerial(BigInteger i) throws DigiDocException {
        DigiDocException ex = validateCertSerial(i);
        if (ex != null) throw ex;
        m_certSerial = i;
    }

    /**
     * Helper method to validate a certSerial
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateCertSerial(BigInteger i) {
        DigiDocException ex = null;
        if (i == null) // check the uri somehow ???
            ex = new DigiDocException(DigiDocException.ERR_CERT_SERIAL, "Certificates serial number cannot be empty!",
                            null);
        return ex;
    }

    /**
     * Returns the count of claimedRole objects
     * 
     * @return count of Reference objects
     */
    public int countClaimedRoles() {
        return ((m_claimedRoles == null) ? 0 : m_claimedRoles.size());
    }

    /**
     * Adds a new reference object
     * 
     * @param ref
     *            Reference object to add
     */
    public void addClaimedRole(String role) {
        if (m_claimedRoles == null) m_claimedRoles = new ArrayList<String>();
        m_claimedRoles.add(role);
    }

    /**
     * Returns the desired claimedRole object
     * 
     * @param idx
     *            index of the claimedRole object
     * @return desired claimedRole object
     */
    public String getClaimedRole(int idx) {
        return (String) m_claimedRoles.get(idx);
    }

    /**
     * Helper method to validate the whole SignedProperties object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate() {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = validateId(m_id);
        if (ex != null) errs.add(ex);
        ex = validateTarget(m_target);
        if (ex != null) errs.add(ex);
        if (!m_sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)) {
            ex = validateCertId(m_certId);
            if (ex != null) errs.add(ex);
        }
        ex = validateSigningTime(m_signingTime);
        if (ex != null) errs.add(ex);
        ex = validateCertDigestAlgorithm(m_certDigestAlgorithm);
        if (ex != null) errs.add(ex);
        ex = validateCertDigestValue(m_certDigestValue);
        if (ex != null) errs.add(ex);
        ex = validateCertSerial(m_certSerial);
        if (ex != null) errs.add(ex);
        // claimed roles
        // and signature production place are optional
        return errs;
    }

    public String getSignedDataObjectProperties() {
        return m_SignedDataObjectProperties;
    }

    public void setSignedDataObjectProperties(String signedDataObjectProperties) {
        m_SignedDataObjectProperties = signedDataObjectProperties;
    }

    public String getDataObjectFormat() {
        return m_DataObjectFormat;
    }

    public void setDataObjectFormat(String dataObjectFormat) {
        m_DataObjectFormat = dataObjectFormat;
    }
    
    public Signature getSignature() {
        return m_sig;
    }
}
