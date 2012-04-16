/*
 * CertValue.java
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;

/**
 * Models the ETSI <X509Certificate> and <EncapsulatedX509Certificate> elements.
 * Holds certificate data. Such elements will be serialized under the
 * <CertificateValues> and <X509Data> elements
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class CertValue implements Serializable {

    private String id;
    /** parent object - Signature ref */
    private Signature signature;

    private int type = CERTVAL_TYPE_UNKNOWN;

    private X509Certificate certificate;

    /** possible cert value type values */
    public static final int CERTVAL_TYPE_UNKNOWN = 0;
    public static final int CERTVAL_TYPE_SIGNER = 1;
    public static final int CERTVAL_TYPE_RESPONDER = 2;
    public static final int CERTVAL_TYPE_TSA = 3;
    // IS FIX CACERT
    public static final int CERTVAL_TYPE_CA = 4;

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature sig) {
        signature = sig;
    }

    public String getId() {
        return id;
    }

    public void setId(String str) {
        id = str;
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
        if (ex != null)
            throw ex;
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
        // IS FIX CACERT
        if (n < 0 || n > CERTVAL_TYPE_CA)
            ex = new DigiDocException(DigiDocException.ERR_CERTID_TYPE, "Invalid CertValue type", null);
        return ex;
    }

    public X509Certificate getCert() {
        return certificate;
    }

    public void setCert(X509Certificate cert) {
        certificate = cert;
    }

    /**
     * Converts the CompleteCertificateRefs to XML form
     * 
     * @return XML representation of CompleteCertificateRefs
     */
    public byte[] toXML() throws DigiDocException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            if (type == CERTVAL_TYPE_SIGNER) {
                bos.write(ConvertUtils.str2data("<X509Certificate>"));
                try {
                    bos.write(ConvertUtils.str2data(Base64Util.encode(certificate.getEncoded(), 64)));
                } catch (CertificateEncodingException ex) {
                    DigiDocException.handleException(ex, DigiDocException.ERR_ENCODING);
                }
                bos.write(ConvertUtils.str2data("</X509Certificate>"));
            }
            if (type == CERTVAL_TYPE_RESPONDER || type == CERTVAL_TYPE_TSA ||
            // IS FIX CACERT
                    type == CERTVAL_TYPE_CA) {
                bos.write(ConvertUtils.str2data("<EncapsulatedX509Certificate Id=\""));
                bos.write(ConvertUtils.str2data(id));
                bos.write(ConvertUtils.str2data("\">\n"));
                try {
                    bos.write(ConvertUtils.str2data(Base64Util.encode(certificate.getEncoded(), 64)));
                } catch (CertificateEncodingException ex) {
                    DigiDocException.handleException(ex, DigiDocException.ERR_ENCODING);
                }
                bos.write(ConvertUtils.str2data("</EncapsulatedX509Certificate>\n"));

            }
        } catch (IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Returns the stringified form of CompleteCertificateRefs
     * 
     * @return CompleteCertificateRefs string representation
     */
    public String toString() {
        try {
            return new String(toXML());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

}
