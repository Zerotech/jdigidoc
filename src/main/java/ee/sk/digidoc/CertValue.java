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

import java.io.Serializable;
import java.security.cert.X509Certificate;

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
    public static final int CERTVAL_TYPE_CA = 4;
    public static final int CERTVAL_TYPE_RESPONDER_CA = 5;
    
    /**
     * Creates new CertValue
     * and initializes everything to null
     */
    public CertValue() {}
    
    /**
     * Parametrized constructor
     * 
     * @param id id atribute value
     * @param cert certificate
     * @param type cert value type
     * @param sig Signature ref
     */
    public CertValue(String id, X509Certificate cert, int type, Signature sig) {
        this.id = id;
        this.signature = sig;
        this.certificate = cert;
        this.type = type;
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
        if (n < 0 || n > CERTVAL_TYPE_RESPONDER_CA)
            ex = new DigiDocException(DigiDocException.ERR_CERTID_TYPE, "Invalid CertValue type", null);
        return ex;
    }

    public X509Certificate getCert() {
        return certificate;
    }

    public void setCert(X509Certificate cert) {
        certificate = cert;
    }
}
