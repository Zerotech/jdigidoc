package ee.sk.digidoc.services;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.crypto.Cipher;

import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Reference;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.TimestampInfo;
import ee.sk.digidoc.UnsignedProperties;

public class VerificationServiceImpl {

    private TimestampService timestampService;
    private CAService caService;
    private CRLService crlService; 
    private CanonicalizationService canonicalizationService;
    private String verifyAlgorithm;
    private NotaryService notaryService;
    // old MAX_TSA_TIME_ERR_SECS
    private int maxTSATimeErrSecs = 0;
    
    // old DIGIDOC_SIGNATURE_VERIFIER
    private String signatureVerifier = "OCSP";
    
    
    public VerificationServiceImpl(
            CAService caService, 
            NotaryService notaryService,
            String verifyAlgorithm) {
        this.caService = caService;
        this.notaryService = notaryService;
        this.verifyAlgorithm = verifyAlgorithm;
    }
    
    /**
     * Helper method to verify the whole SignedDoc object. Use this method to
     * verify all signatures
     * 
     * @param checkDate
     *            Date on which to check the signature validity
     * @param demandConfirmation
     *            true if you demand OCSP confirmation from every signature
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> verify(SignedDoc signedDoc, boolean checkDate, boolean demandConfirmation) {
        List<DigiDocException> errs = validate(signedDoc, false);
        for (int i = 0; i < signedDoc.countSignatures(); i++) {
            Signature sig = signedDoc.getSignature(i);
            List<DigiDocException> e = verify(sig, signedDoc, checkDate, demandConfirmation);
            if (!e.isEmpty())
                errs.addAll(e);
        }
        if (signedDoc.countSignatures() == 0) {
            errs.add(new DigiDocException(DigiDocException.ERR_NOT_SIGNED, "This document is not signed!", null));
        }
        return errs;
    }

    
    
    /**
     * Helper method to validate the whole SignedDoc object
     * 
     * @param bStrong
     *            flag that specifies if Id atribute value is to be rigorously
     *            checked (according to digidoc format) or only as required by
     *            XML-DSIG
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate(SignedDoc signedDoc, boolean bStrong) {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = signedDoc.validateFormat(signedDoc.getFormat());
        if (ex != null)
            errs.add(ex);
        ex = signedDoc.validateVersion(signedDoc.getVersion());
        if (ex != null)
            errs.add(ex);
        for (int i = 0; i < signedDoc.countDataFiles(); i++) {
            DataFile df = signedDoc.getDataFile(i);
            List<DigiDocException> e = df.validate(bStrong);
            if (!e.isEmpty())
                errs.addAll(e);
        }
        for (int i = 0; i < signedDoc.countSignatures(); i++) {
            Signature sig = signedDoc.getSignature(i);
            List<DigiDocException> e = validate(sig);
            if (!e.isEmpty())
                errs.addAll(e);
        }
        return errs;
    }


    /**
     * Helper method to verify the whole SignedDoc object. Use this method to
     * verify all signatures
     * 
     * @param checkDate
     *            Date on which to check the signature validity
     * @param bUseOcsp
     *            true if you demand OCSP confirmation from every signature.
     *            False if you want to check against CRL.
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> verifyOcspOrCrl(SignedDoc signedDoc, boolean checkDate, boolean bUseOcsp) {
        List<DigiDocException> errs = validate(signedDoc, false);
        for (int i = 0; i < signedDoc.countSignatures(); i++) {
            Signature sig = signedDoc.getSignature(i);
            List<DigiDocException> e = verifyOcspOrCrl(sig, signedDoc, checkDate, bUseOcsp, timestampService, crlService, canonicalizationService, verifyAlgorithm);
            if (!e.isEmpty())
                errs.addAll(e);
        }
        if (signedDoc.countSignatures() == 0) {
            errs.add(new DigiDocException(DigiDocException.ERR_NOT_SIGNED, "This document is not signed!", null));
        }
        return errs;
    }

    
    /**
     * Verifies this signature
     * 
     * @param sdoc
     *            parent doc object
     * @param checkDate
     *            Date on which to check the signature validity
     * @param demandConfirmation
     *            true if you demand OCSP confirmation from every signature
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> verify(
            Signature signature,
            SignedDoc sdoc, 
            boolean checkDate, 
            boolean demandConfirmation) {
        Date do1 = null, dt1 = null, dt2 = null;
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        // check the DataFile digests
        for (int i = 0; i < sdoc.countDataFiles(); i++) {
            DataFile df = sdoc.getDataFile(i);
            // System.out.println("Check digest for DF: " + df.getId());
            Reference ref = signature.getSignedInfo().getReferenceForDataFile(df);
            byte[] dfDig = null;
            try {
                dfDig = df.getDigest();
            } catch (DigiDocException ex) {
                errs.add(ex);
            }
            if (ref != null) {
                // System.out.println("Compare it to: " +
                // Base64Util.encode(ref.getDigestValue(), 0));
                if (!SignedDoc.compareDigests(ref.getDigestValue(), dfDig)) {
                    errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE, "Bad digest for DataFile: "
                            + df.getId(), null));
                    // System.out.println("BAD DIGEST");
                }
                // else System.out.println("GOOD DIGEST");
            } else {
                // System.out.println("No Reference");
                errs.add(new DigiDocException(DigiDocException.ERR_DATA_FILE_NOT_SIGNED,
                        "No Reference element for DataFile: " + df.getId(), null));
            }
            // if this is a detatched file and the file
            // referred by this entry actually exists,
            // then go and check it's digest
            // If the datafile doesn't exist the
            // just trust whatever is in the XML
            if (df.getContentType().equals(DataFile.CONTENT_DETATCHED)) {
                File fTest = new File(df.getFileName());
                if (fTest.canRead()) {
                    // System.out.println("Check detatched file: " +
                    // fTest.getAbsolutePath());
                    byte[] realDigest = null;
                    byte[] detDigest = null;
                    try {
                        realDigest = df.calculateDetatchedFileDigest();
                        detDigest = df.getDigestValue();
                    } catch (DigiDocException ex) {
                        errs.add(ex);
                    }
                    if (!SignedDoc.compareDigests(detDigest, realDigest)) {
                        errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE,
                                "Bad digest for detatched file: " + df.getFileName(), null));
                    }
                }
                // else System.out.println("Cannot read detatched file: " +
                // fTest.getAbsolutePath());
            }
        }
        // check signed properties digest
        Reference ref2 = signature.getSignedInfo().getReferenceForSignedProperties(signature.getSignedProperties());
        if (ref2 != null) {
            byte[] spDig = null;
            try {
                spDig = signature.getSignedProperties().calculateDigest(canonicalizationService);
                // System.out.println("SignedProp real digest: " +
                // Base64Util.encode(spDig, 0));
            } catch (DigiDocException ex) {
                errs.add(ex);
            }
            // System.out.println("Compare it to: " +
            // Base64Util.encode(ref2.getDigestValue(), 0));
            if (!SignedDoc.compareDigests(ref2.getDigestValue(), spDig)) {
                errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE, "Bad digest for SignedProperties: "
                        + signature.getSignedProperties().getId(), null));
                // System.out.println("BAD DIGEST");
            }
            // else System.out.println("GOOD DIGEST");
        } else {
            errs.add(new DigiDocException(DigiDocException.ERR_SIG_PROP_NOT_SIGNED,
                    "No Reference element for SignedProperties: " + signature.getSignedProperties().getId(), null));
        }
        // verify signature value
        try {
            byte[] dig = signature.getSignedInfo().calculateDigest(canonicalizationService);
            // System.out.println("SignedInfo real digest: " +
            // Base64Util.encode(dig, 0) + " hex: " + SignedDoc.bin2hex(dig));
            verify(dig, signature.getSignatureValue().getValue(), signature.getKeyInfo().getSignersCertificate());
            // System.out.println("GOOD DIGEST");
        } catch (DigiDocException ex) {
            errs.add(ex);
            System.out.println("BAD DIGEST");
        }
        // verify signers cert...
        // check the certs validity dates
        try {
            if (checkDate)
                signature.getKeyInfo().getSignersCertificate().checkValidity(signature.getSignedProperties().getSigningTime());
        } catch (Exception ex) {
            errs.add(new DigiDocException(DigiDocException.ERR_CERT_EXPIRED, "Signers certificate has expired!", null));
        }
        // check certificates CA
        try {
            caService.verifyCertificate(signature.getKeyInfo().getSignersCertificate());
        } catch (DigiDocException ex) {
            errs.add(ex);
        }
        // if we check signatures using CRL
        if (signatureVerifier != null && signatureVerifier.equals("CRL")) {
            try {
                crlService.checkCertificate(signature.getKeyInfo().getSignersCertificate(), new Date());
            } catch (DigiDocException ex) {
                errs.add(ex);
            }
        }
        // check confirmation
        if (signature.getUnsignedProperties() != null) {
            List<DigiDocException> e = verify(signature.getUnsignedProperties(), sdoc);
            if (!e.isEmpty())
                errs.addAll(e);
            if (signature.getUnsignedProperties().getNotary() != null)
                do1 = signature.getUnsignedProperties().getNotary().getProducedAt();
        } else { // not OCSP confirmation
            if (demandConfirmation)
                errs.add(new DigiDocException(DigiDocException.ERR_NO_CONFIRMATION,
                        "Signature has no OCSP confirmation!", null));
        }
        // verify timestamps
        List<X509Certificate> tsaCerts = signature.findTSACerts();
        if (signature.getTimestamps() != null && signature.getTimestamps().size() > 0) {
            List<DigiDocException> e = timestampService.verifySignaturesTimestamps(signature);
            if (!e.isEmpty())
                errs.addAll(e);
            for (int i = 0; i < signature.getTimestamps().size(); i++) {
                TimestampInfo ts = (TimestampInfo) signature.getTimestamps().get(i);
                if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE)
                    dt1 = ts.getTime();
                if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS)
                    dt2 = ts.getTime();
            }

            dt1 = new Date(dt1.getTime() - (this.maxTSATimeErrSecs * 1000));
            dt2 = new Date(dt2.getTime() + (this.maxTSATimeErrSecs * 1000));

            if (dt2.before(dt1))
                errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                        "SignAndRefsTimeStamp is before SignatureTimeStamp", null));
            if (do1.before(dt1) || do1.after(dt2))
                errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                        "OCSP time is not between SignAndRefsTimeStamp and SignatureTimeStamp", null));
        }
        return errs;
    }


    /**
     * Helper method to validate the whole Signature object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate(Signature signature) {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = signature.validateId(signature.getId());
        if (ex != null)
            errs.add(ex);
        List<DigiDocException> e = signature.getSignedInfo().validate();
        if (!e.isEmpty())
            errs.addAll(e);
        // VS: 2.2.24 - fix to allowe Signature without SignatureValue -
        // incomplete sig
        // if(m_signatureValue != null)
        e = signature.getSignatureValue().validate();
        if (!e.isEmpty())
            errs.addAll(e);
        e = signature.getKeyInfo().validate();
        if (!e.isEmpty())
            errs.addAll(e);
        e = signature.getSignedProperties().validate();
        if (!e.isEmpty())
            errs.addAll(e);
        if (signature.getUnsignedProperties() != null) {
            e = signature.getUnsignedProperties().validate();
            if (!e.isEmpty())
                errs.addAll(e);
        }
        return errs;
    }

    
    
    
    
    
    
    
    /**
     * Verifies this signature. Demands either OCSP confirmation or uses CRL to
     * check signature validity.
     * 
     * @param sdoc
     *            parent doc object
     * @param checkDate
     *            Date on which to check the signature validity
     * @param bUseOcsp
     *            true if you demand OCSP confirmation from every signature.
     *            False if you want to check against CRL.
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> verifyOcspOrCrl(
            Signature signature,
            SignedDoc sdoc, 
            boolean checkDate, 
            boolean bUseOcsp, 
            TimestampService timestampService, 
            CRLService crlService, 
            CanonicalizationService canonicalizationService,
            String verifyAlgorithm) {
        Date do1 = null, dt1 = null, dt2 = null;
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        // check the DataFile digests
        for (int i = 0; i < sdoc.countDataFiles(); i++) {
            DataFile df = sdoc.getDataFile(i);
            // System.out.println("Check digest for DF: " + df.getId());
            Reference ref = signature.getSignedInfo().getReferenceForDataFile(df);
            byte[] dfDig = null;
            try {
                dfDig = df.getDigest();
            } catch (DigiDocException ex) {
                errs.add(ex);
            }
            if (ref != null) {
                // System.out.println("Compare it to: " +
                // Base64Util.encode(ref.getDigestValue(), 0));
                if (!SignedDoc.compareDigests(ref.getDigestValue(), dfDig)) {
                    errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE, "Bad digest for DataFile: "
                            + df.getId(), null));
                    // System.out.println("BAD DIGEST");
                }
                // else System.out.println("GOOD DIGEST");
            } else {
                // System.out.println("No Reference");
                errs.add(new DigiDocException(DigiDocException.ERR_DATA_FILE_NOT_SIGNED,
                        "No Reference element for DataFile: " + df.getId(), null));
            }
            // if this is a detatched file and the file
            // referred by this entry actually exists,
            // then go and check it's digest
            // If the datafile doesn't exist the
            // just trust whatever is in the XML
            if (df.getContentType().equals(DataFile.CONTENT_DETATCHED)) {
                File fTest = new File(df.getFileName());
                if (fTest.canRead()) {
                    // System.out.println("Check detatched file: " +
                    // fTest.getAbsolutePath());
                    byte[] realDigest = null;
                    byte[] detDigest = null;
                    try {
                        realDigest = df.calculateDetatchedFileDigest();
                        detDigest = df.getDigestValue();
                    } catch (DigiDocException ex) {
                        errs.add(ex);
                    }
                    if (!SignedDoc.compareDigests(detDigest, realDigest)) {
                        errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE,
                                "Bad digest for detatched file: " + df.getFileName(), null));
                    }
                }
                // else System.out.println("Cannot read detatched file: " +
                // fTest.getAbsolutePath());
            }
        }
        // check signed properties digest
        Reference ref2 = signature.getSignedInfo().getReferenceForSignedProperties(signature.getSignedProperties());
        if (ref2 != null) {
            byte[] spDig = null;
            try {
                spDig = signature.getSignedProperties().calculateDigest(canonicalizationService);
                // System.out.println("SignedProp real digest: " +
                // Base64Util.encode(spDig, 0));
            } catch (DigiDocException ex) {
                errs.add(ex);
            }
            // System.out.println("Compare it to: " +
            // Base64Util.encode(ref2.getDigestValue(), 0));
            if (!SignedDoc.compareDigests(ref2.getDigestValue(), spDig)) {
                errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE, "Bad digest for SignedProperties: "
                        + signature.getSignedProperties().getId(), null));
                // System.out.println("BAD DIGEST");
            }
            // else System.out.println("GOOD DIGEST");
        } else {
            errs.add(new DigiDocException(DigiDocException.ERR_SIG_PROP_NOT_SIGNED,
                    "No Reference element for SignedProperties: " + signature.getSignedProperties().getId(), null));
        }
        // verify signature value
        try {
            byte[] dig = signature.getSignedInfo().calculateDigest(canonicalizationService);
            verify(dig, signature.getSignatureValue().getValue(), signature.getKeyInfo().getSignersCertificate());
        } catch (DigiDocException ex) {
            errs.add(ex);
            System.out.println("BAD DIGEST");
        }
        // verify signers cert...
        // check the certs validity dates
        try {
            if (checkDate)
                signature.getKeyInfo().getSignersCertificate().checkValidity(signature.getSignedProperties().getSigningTime());
        } catch (Exception ex) {
            errs.add(new DigiDocException(DigiDocException.ERR_CERT_EXPIRED, "Signers certificate has expired!", null));
        }
        // check certificates CA
        try {
            caService.verifyCertificate(signature.getKeyInfo().getSignersCertificate());
        } catch (DigiDocException ex) {
            errs.add(ex);
        }
        // switch OCSP or CRL verification
        if (bUseOcsp) { // use OCSP
            // check confirmation
            if (signature.getUnsignedProperties() != null) {
                List<DigiDocException> e = verify(signature.getUnsignedProperties(), sdoc);
                if (!e.isEmpty())
                    errs.addAll(e);
            } else { // not OCSP confirmation
                errs.add(new DigiDocException(DigiDocException.ERR_NO_CONFIRMATION,
                        "Signature has no OCSP confirmation!", null));
            }
            // verify timestamps
            List<X509Certificate> tsaCerts = signature.findTSACerts();
            if (signature.getTimestamps().size() > 0) {
                List<DigiDocException> e = timestampService.verifySignaturesTimestamps(signature);
                if (!e.isEmpty())
                    errs.addAll(e);
                for (int i = 0; i < signature.getTimestamps().size(); i++) {
                    TimestampInfo ts = (TimestampInfo) signature.getTimestamps().get(i);
                    if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE)
                        dt1 = ts.getTime();
                    if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS)
                        dt2 = ts.getTime();
                }

                dt1 = new Date(dt1.getTime() - (this.maxTSATimeErrSecs * 1000));
                dt2 = new Date(dt2.getTime() + (this.maxTSATimeErrSecs * 1000));

                if (dt2.before(dt1))
                    errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                            "SignAndRefsTimeStamp is before SignatureTimeStamp", null));
                if (do1.before(dt1) || do1.after(dt2))
                    errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                            "OCSP time is not between SignAndRefsTimeStamp and SignatureTimeStamp", null));
            }
        } else {
            try {
                crlService.checkCertificate(signature.getKeyInfo().getSignersCertificate(), new Date());
            } catch (DigiDocException ex) {
                errs.add(ex);
            }
        }
        return errs;
    }

    
    /**
     * Verifies this confirmation
     * 
     * @param sdoc
     *            parent doc object
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> verify(UnsignedProperties unsignedProperties, SignedDoc sdoc) {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        // verify notary certs serial number using CompleteCertificateRefs
        X509Certificate cert = unsignedProperties.getRespondersCertificate();
        // System.out.println("Responders cert: " +
        // getRespondersCertificate().getSerialNumber() +
        // " complete cert refs nr: " + m_certRefs.getCertSerial());
        if (cert == null) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "No notarys certificate!", null));
            return errs;
        }
        if (cert != null && !cert.getSerialNumber().equals(unsignedProperties.getCompleteCertificateRefs().getCertSerial())) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "Wrong notarys certificate!", null));
        }
        // verify notary certs digest using CompleteCertificateRefs
        try {
            byte[] digest = SignedDoc.digest(cert.getEncoded());
            if (!SignedDoc.compareDigests(digest, unsignedProperties.getCompleteCertificateRefs().getCertDigestValue()))
                errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                        "Notary certificates digest doesn't match!", null));
        } catch (DigiDocException ex) {
            errs.add(ex);
        } catch (Exception ex) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                    "Error calculating notary certificate digest!", null));
        }
        // verify notarys digest using CompleteRevocationRefs
        try {
            byte[] ocspData = unsignedProperties.getNotary().getOcspResponseData();
            // System.out.println("OCSP data len: " + ocspData.length);
            byte[] digest1 = SignedDoc.digest(ocspData);
            // System.out.println("Calculated digest: " +
            // Base64Util.encode(digest1, 0));
            byte[] digest2 = unsignedProperties.getCompleteRevocationRefs().getDigestValue();
            // System.out.println("Real digest: " + Base64Util.encode(digest2,
            // 0));
            if (!SignedDoc.compareDigests(digest1, digest2))
                errs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "Notarys digest doesn't match!", null));
        } catch (DigiDocException ex) {
            errs.add(ex);
        }
        // verify notary status
        try {
            notaryService.parseAndVerifyResponse(unsignedProperties.getSignature(), unsignedProperties.getNotary());
        } catch (DigiDocException ex) {
            errs.add(ex);
        }
        return errs;
    }
    
    
    

    /**
     * Verifies the siganture
     * 
     * @param digest
     *            input data digest
     * @param signature
     *            signature value
     * @param cert
     *            certificate to be used on verify
     * @param verifyAlgorithm old DIGIDOC_VERIFY_ALGORITHM.
     * @return true if signature verifies
     */
    public boolean verify(byte[] digest, byte[] signature, X509Certificate cert) throws DigiDocException {
        boolean rc = false;
        try {
            // VS - for some reason this JDK internal method sometimes failes

            // System.out.println("Verify digest: " + bin2hex(digest) +
            // " signature: " + Base64Util.encode(signature, 0));
            /*
             * // check keystore... java.security.Signature sig =
             * java.security.Signature.getInstance("SHA1withRSA");
             * sig.initVerify
             * ((java.security.interfaces.RSAPublicKey)cert.getPublicKey());
             * sig.update(digest); rc = sig.verify(signature);
             */
            Cipher cryptoEngine = Cipher.getInstance(verifyAlgorithm, "BC");
            cryptoEngine.init(Cipher.DECRYPT_MODE, cert);
            byte[] decryptedDigestValue = cryptoEngine.doFinal(signature);
            byte[] cdigest = new byte[digest.length];
            System.arraycopy(decryptedDigestValue, decryptedDigestValue.length - digest.length, cdigest, 0,
                    digest.length);
            // System.out.println("Decrypted digest: \'" + bin2hex(cdigest) +
            // "\'");
            // now compare the digests
            rc = SignedDoc.compareDigests(digest, cdigest);

            // System.out.println("Result: " + rc);
            if (!rc)
                throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid signature value!", null);
        } catch (DigiDocException ex) {
            throw ex; // pass it on, but check other exceptions
        } catch (Exception ex) {
            // System.out.println("Exception: " + ex);
            DigiDocException.handleException(ex, DigiDocException.ERR_VERIFY);
        }
        return rc;
    }


}
