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

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

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
    private List<Notary> notaries;
    private static Logger LOG = Logger.getLogger(UnsignedProperties.class);

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
    public UnsignedProperties(Signature sig, CompleteCertificateRefs crefs, CompleteRevocationRefs rrefs)
                    throws DigiDocException {
        signature = sig;
        setCompleteCertificateRefs(crefs);
        setCompleteRevocationRefs(rrefs);
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
            if (cval != null) cert = cval.getCert();
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
        if (signature != null && cert != null) {
            CertValue cval = signature.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
            cval.setId(signature.getId() + "-RESPONDER_CERT");
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
        if (cert == null
                        && (signature.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) || (signature
                                        .getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                                        && signature.getProfile() != null && (signature.getProfile().equals(
                                        SignedDoc.BDOC_PROFILE_TS) || signature.getProfile().equals(
                                        SignedDoc.BDOC_PROFILE_TM)))))
            ex = new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "Notarys certificate is required", null);
        return ex;
    }
    
    /**
     * Get the n-th Notary object
     * 
     * @param nIdx Notary index
     * @return Notary object
     */
    public Notary getNotaryById(int index) {
        if (notaries != null && index < notaries.size())
            return notaries.get(index);
        else
            return null;
    }
    
    /**
     * Add a new Notary
     * 
     * @param not Notary object
     */
    public void addNotary(Notary not) {
        if (notaries == null) notaries = new ArrayList<Notary>();
        notaries.add(not);
    }
    
    /**
     * Count the number of Notary objects
     * 
     * @return number of Notary objects
     */
    public int countNotaries() {
        return (notaries != null) ? notaries.size() : 0;
    }
    
    /**
     * Accessor for notary attribute
     * 
     * @return value of notary attribute
     */
    public Notary getNotary() {
        return getNotaryById(0);
    }
    
    /**
     * Accessor for notary attribute
     * 
     * @return value of notary attribute
     */
    public Notary getLastNotary() {
        return getNotaryById(countNotaries() - 1);
    }
    
    /**
     * Mutator for notary attribute
     * 
     * @param str new value for notary attribute
     * @throws DigiDocException for validation errors
     */
    public void setNotary(Notary not) throws DigiDocException {
        addNotary(not);
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
        if (cert == null) ex = validateRespondersCertificate(cert);
        if (ex != null) errs.add(ex);
        List<DigiDocException> e = null;
        if (completeCertRefs != null) {
            e = completeCertRefs.validate();
            if (!e.isEmpty()) errs.addAll(e);
        }
        if (completeRevRefs != null) {
            e = completeRevRefs.validate();
            if (!e.isEmpty()) errs.addAll(e);
        }
        return errs;
    }
}
