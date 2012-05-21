/*
 * UnsignedProperties.java
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import ee.sk.utils.ConvertUtils;

/**
 * Models the unsigned properties of a signature.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class UnsignedProperties implements Serializable {

    private Signature signature;
    private CompleteCertificateRefs completeCertRefs;
    private CompleteRevocationRefs completeRevRefs;
    private Notary notary;


    public UnsignedProperties(Signature sig) {
        signature = sig;
    }

    /**
     * Creates new UsignedProperties
     * 
     * @param sig
     *            signature reference
     * @param crefs
     *            responders cert digest & info
     * @param rrefs
     *            OCSP response digest & info
     * @param rcert
     *            responders cert
     * @param not
     *            OCSP response
     */
    public UnsignedProperties(
            Signature sig, 
            CompleteCertificateRefs crefs, 
            CompleteRevocationRefs rrefs,
            X509Certificate rcert, 
            Notary not) throws DigiDocException {
        signature = sig;
        setCompleteCertificateRefs(crefs);
        setCompleteRevocationRefs(rrefs);
        setRespondersCertificate(rcert);
        setNotary(not);
    }

    public CompleteCertificateRefs getCompleteCertificateRefs() {
        return completeCertRefs;
    }

    public Signature getSignature() {
        return signature;
    }

    public void setCompleteCertificateRefs(CompleteCertificateRefs crefs) {
        completeCertRefs = crefs;
    }

    public CompleteRevocationRefs getCompleteRevocationRefs() {
        return completeRevRefs;
    }

    public void setCompleteRevocationRefs(CompleteRevocationRefs refs) {
        completeRevRefs = refs;
    }

    /**
     * Accessor for respondersCertificate attribute
     * 
     * @return value of respondersCertificate attribute
     */
    public X509Certificate getRespondersCertificate() {
        X509Certificate cert = null;
        if (signature != null) {
            CertValue cval = signature.getCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
            if (cval != null)
                cert = cval.getCert();
        }
        return cert;
    }

    /**
     * Mutator for respondersCertificate attribute
     * 
     * @param cert
     *            new value for respondersCertificate attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setRespondersCertificate(X509Certificate cert) throws DigiDocException {
        DigiDocException ex = validateRespondersCertificate(cert);
        if (ex != null)
            throw ex;
        if (signature != null) {
            CertValue cval = signature.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
            cval.setCert(cert);
        }
    }

    /**
     * Helper method to validate a responders cert
     * 
     * @param cert
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateRespondersCertificate(X509Certificate cert) {
        DigiDocException ex = null;
        if (cert == null)
            ex = new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "Notarys certificate is required", null);
        return ex;
    }

    public Notary getNotary() {
        return notary;
    }

    public void setNotary(Notary not) {
        notary = not;
    }


    /**
     * Helper method to validate the whole UnsignedProperties object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate() {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = null;
        X509Certificate cert = getRespondersCertificate();
        if (cert == null)
            ex = validateRespondersCertificate(cert);
        if (ex != null)
            errs.add(ex);
        List<DigiDocException> e = null;
        if (completeCertRefs != null) {
            e = completeCertRefs.validate();
            if (!e.isEmpty())
                errs.addAll(e);
        }
        if (completeRevRefs != null) {
            e = completeRevRefs.validate();
            if (!e.isEmpty())
                errs.addAll(e);
        }
        // notary ???

        return errs;
    }

    /**
     * Converts the UnsignedProperties to XML form
     * 
     * @return XML representation of UnsignedProperties
     */
    public byte[] toXML() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            if (signature.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)) {
                bos.write(ConvertUtils.str2data("<UnsignedProperties>"));
            } else if (signature.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                bos.write(ConvertUtils.str2data("<UnsignedProperties xmlns=\""));
                bos.write(ConvertUtils.str2data(SignedDoc.XMLNS_XADES_123 + "\">\n"));
            } else {
                bos.write(ConvertUtils.str2data("<UnsignedProperties Target=\"#"));
                bos.write(ConvertUtils.str2data(signature.getId()));
                bos.write(ConvertUtils.str2data("\">"));
            }
            bos.write(ConvertUtils.str2data("\n<UnsignedSignatureProperties>"));

            if (signature.getTimestampInfo(TimestampInfo.TIMESTAMP_TYPE_SIGNATURE) != null) {
                bos.write(signature.getTimestampInfo(TimestampInfo.TIMESTAMP_TYPE_SIGNATURE).toXML());
            }

            if (completeCertRefs != null)
                bos.write(completeCertRefs.toXML());
            if (completeRevRefs != null) {
                bos.write(completeRevRefs.toXML());
                bos.write(ConvertUtils.str2data("\n"));
            }
            
            bos.write(ConvertUtils.str2data("<CertificateValues>\n"));
            
            for (int i = 0; i < signature.countCertValues(); i++) {
                CertValue cval = signature.getCertValue(i);
                if (cval.getType() != CertValue.CERTVAL_TYPE_SIGNER)
                    bos.write(cval.toXML());
            }
            
            bos.write(ConvertUtils.str2data("</CertificateValues>"));
            
            if (notary != null) {
                bos.write(ConvertUtils.str2data("\n"));
                bos.write(notary.toXML(signature.getSignedDoc().getVersion()));
            }
            
            bos.write(ConvertUtils.str2data("</UnsignedSignatureProperties>\n</UnsignedProperties>"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bos.toByteArray();
    }

    /**
     * Returns the stringified form of UnsignedProperties
     * 
     * @return UnsignedProperties string representation
     */
    public String toString() {
        String str = null;
        try {
            str = new String(toXML());
        } catch (Exception ex) {
        }
        return str;
    }
}
