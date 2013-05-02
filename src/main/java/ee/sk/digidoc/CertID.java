/*
 * CertID.java
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
import java.util.List;

import ee.sk.utils.DDUtils;

/**
 * Models the ETSI <Cert> element Holds info about a certificate but not the
 * certificate itself. Such elements will be serialized under the
 * <CompleteCertificateRefs> element
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class CertID implements Serializable {

    private String id;

    private String digestAlgorithm;

    private byte[] digestValue;
    
    private String uri;

    private String issuerDN;

    private BigInteger issuerSerialNumber;
    /** parent object */
    private Signature signature;

    private int type = CERTID_TYPE_UNKNOWN;

    /** possible certid type values */
    public static final int CERTID_TYPE_UNKNOWN = 0;
    public static final int CERTID_TYPE_SIGNER = 1;
    public static final int CERTID_TYPE_RESPONDER = 2;
    public static final int CERTID_TYPE_TSA = 3;
    // IS FIX CACERT
    public static final int CERTID_TYPE_CA = 4;
    public static final int CERTID_TYPE_RESPONDER_CA = 5;

    /**
     * Creates new CertID and initializes everything to null
     */
    public CertID() {}

    /**
     * Creates new CertID
     * 
     * @param certId
     *            OCSP responders cert id (in XML)
     * @param digAlg
     *            OCSP responders certs digest algorithm id/uri
     * @param digest
     *            OCSP responders certs digest
     * @param serial
     *            OCSP responders certs issuers serial number
     * @param type
     *            CertID type: signer, responder or tsa
     * @throws DigiDocException
     *             for validation errors
     */
    public CertID(String certId, String digAlg, byte[] digest, BigInteger serial, String issuer, int type)
                    throws DigiDocException {
        setId(certId);
        setDigestAlgorithm(digAlg);
        setDigestValue(digest);
        setSerial(serial);
        if (issuer != null) setIssuer(issuer);
        setType(type);
        signature = null;
    }

    /**
     * Creates new CertID by using default values for id and cert
     * 
     * @param sig
     *            Signature object
     * @param cert
     *            certificate for creating this ref data
     * @param type
     *            CertID type: signer, responder or tsa or ca
     * @throws DigiDocException
     *             for validation errors
     */
    public CertID(Signature sig, X509Certificate cert, int type) throws DigiDocException {
        if (type == CERTID_TYPE_SIGNER) {
            setId(sig.getId() + "-CERTINFO");
        }
        if (type == CERTID_TYPE_RESPONDER) {
            setId(sig.getId() + "-RESPONDER_CERTINFO");
        }
        String digType = DDUtils.getDefaultDigestType(sig.getSignedDoc());
        setDigestAlgorithm(DDUtils.digType2Alg(digType));
        byte[] digest = null;
        try {
            digest = DDUtils.digestOfType(cert.getEncoded(), digType);
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        setDigestValue(digest);
        setSerial(cert.getSerialNumber());
        setIssuer(cert.getIssuerX500Principal().getName("RFC1779"));
        setType(type);
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature sig) {
        signature = sig;
    }

    public String getId() {
        return id;
    }

    /**
     * Mutator for certId attribute
     * 
     * @param str
     *            new value for certId attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setId(String str) throws DigiDocException {
        if (signature != null && signature.getSignedDoc() != null
                        && !signature.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)) {
            DigiDocException ex = validateId(str);
            if (ex != null) throw ex;
        }
        id = str;
    }

    /**
     * Helper method to validate an certificate id
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str) {
        DigiDocException ex = null;
        if (str == null && !signature.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)
                        && !signature.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                        && type == CERTID_TYPE_RESPONDER)
            ex = new DigiDocException(DigiDocException.ERR_RESPONDER_CERT_ID,
                            "Cert Id must be in form: <signature-id>-RESPONDER_CERTINFO", null);
        return ex;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }
    
    /**
     * Accessor for URI attribute
     * 
     * @return value of URI attribute
     */
    public String getUri() {
        return uri;
    }
    
    /**
     * Mutator for URI attribute
     * 
     * @param str new value for URI attribute
     */
    public void setUri(String str) {
        uri = str;
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
        if (ex != null) throw ex;
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
        if (str == null
                        || (!str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM) && !str
                                        .equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1)))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM,
                            "Currently supports only SHA1 or SHA256 digest algorithm", null);
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
        if (ex != null) throw ex;
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
        if (data == null
                        || (data.length != SignedDoc.SHA1_DIGEST_LENGTH && data.length != SignedDoc.SHA256_DIGEST_LENGTH))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH, "Invalid digest length", null);
        return ex;
    }

    public BigInteger getSerial() {
        return issuerSerialNumber;
    }

    /**
     * Mutator for serial attribute
     * 
     * @param str
     *            new value for serial attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setSerial(BigInteger i) throws DigiDocException {
        DigiDocException ex = validateSerial(i);
        if (ex != null) throw ex;
        issuerSerialNumber = i;
    }

    /**
     * Helper method to validate a serial
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateSerial(BigInteger i) {
        DigiDocException ex = null;
        if (i == null) // check the uri somehow ???
            ex = new DigiDocException(DigiDocException.ERR_CERT_SERIAL, "Certificates serial number cannot be empty!",
                            null);
        return ex;
    }

    public String getIssuer() {
        return issuerDN;
    }

    /**
     * Mutator for issuer attribute
     * 
     * @param str
     *            new value for issuer attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setIssuer(String str) throws DigiDocException {
        DigiDocException ex = validateIssuer(str);
        if (ex != null) throw ex;
        issuerDN = str;
    }

    /**
     * Helper method to validate issuer
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateIssuer(String str) {
        DigiDocException ex = null;
        if (str == null && signature != null && signature.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3))
            ex = new DigiDocException(DigiDocException.ERR_CREF_ISSUER, "Issuer name cannot be empty", null);
        return ex;
    }

    public int getType() {
        return type;
    }

    /**
     * Mutator for type attribute
     * 
     * @param n
     *            new value for issuer attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setType(int n) throws DigiDocException {
        DigiDocException ex = validateType(n);
        if (ex != null) throw ex;
        type = n;
    }

    /**
     * Helper method to validate type
     * 
     * @param n
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateType(int n) {
        DigiDocException ex = null;
        if (n < 0 || n > CERTID_TYPE_RESPONDER_CA)
            ex = new DigiDocException(DigiDocException.ERR_CERTID_TYPE, "Invalid CertID type", null);
        return ex;
    }

    /**
     * Helper method to validate the whole CertID object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate() {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = validateId(id);
        if (ex != null) errs.add(ex);
        ex = validateDigestAlgorithm(digestAlgorithm);
        if (ex != null) errs.add(ex);
        ex = validateDigestValue(digestValue);
        if (ex != null) errs.add(ex);
        ex = validateSerial(issuerSerialNumber);
        if (ex != null) errs.add(ex);
        ex = validateIssuer(issuerDN);
        if (ex != null) errs.add(ex);
        ex = validateType(type);
        if (ex != null) errs.add(ex);
        return errs;
    }
}
