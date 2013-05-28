package ee.sk.digidoc.services;

import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

import ee.sk.digidoc.CertID;
import ee.sk.digidoc.CertValue;
import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Notary;
import ee.sk.digidoc.OcspRef;
import ee.sk.digidoc.Reference;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.SignedProperties;
import ee.sk.digidoc.UnsignedProperties;
import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;
import ee.sk.xmlenc.EncryptedData;

public class VerificationServiceImpl {
    
    private static Logger LOG = Logger.getLogger(VerificationServiceImpl.class);
    
    //    private TimestampService timestampService;
    //    private CAService caService;
    private CanonicalizationService canonicalizationService;
    private TrustService trustService;
    private NotaryService notaryService;
    // old MAX_TSA_TIME_ERR_SECS
    //    private int maxTSATimeErrSecs = 0;
    
    private static boolean providerInitialized = false;
    
    private static final String DIGIDOC_VERIFY_ALGORITHM = "RSA/NONE/PKCS1Padding";
    
    private static final String DIG_TYPE_WARNING = "The current BDoc container uses weaker encryption method than officialy accepted in Estonia. "
                    + "We do not recommend you to add signature to this document. There is an option to re-sign this document in a new container.";
    
    public VerificationServiceImpl(TrustService trustService, NotaryService notaryService,
                    CanonicalizationService canonicalizationService) {
        this.trustService = trustService;
        this.notaryService = notaryService;
        this.canonicalizationService = canonicalizationService;
    }
    
    public void initProvider() {
        try {
            if (!providerInitialized) {
                Provider prv = (Provider) Class.forName(EncryptedData.DIGIDOC_SECURITY_PROVIDER).newInstance();
                Security.addProvider(prv);
                providerInitialized = true;
            }
        } catch (Exception ex) {
            LOG.error("Error initting provider: " + ex);
        }
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

            if (!e.isEmpty()) {
                errs.addAll(e);
            }
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
        
        if (ex != null) {
            errs.add(ex);
        }

        ex = signedDoc.validateVersion(signedDoc.getVersion());
        
        if (ex != null) {
            errs.add(ex);
        }
        
        for (int i = 0; i < signedDoc.countDataFiles(); i++) {
            DataFile df = signedDoc.getDataFile(i);
            List<DigiDocException> e = df.validate(bStrong);
            
            if (!e.isEmpty()) {
                errs.addAll(e);
            }

        }
        
        for (int i = 0; i < signedDoc.countSignatures(); i++) {
            Signature sig = signedDoc.getSignature(i);
            List<DigiDocException> e = validate(sig);
            
            if (!e.isEmpty()) {
                errs.addAll(e);
            }

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
    
    //    public List<DigiDocException> verifyOcspOrCrl(SignedDoc signedDoc, boolean checkDate, boolean bUseOcsp) {
    //        List<DigiDocException> errs = validate(signedDoc, false);
    //        
    //        for (int i = 0; i < signedDoc.countSignatures(); i++) {
    //            Signature sig = signedDoc.getSignature(i);
    //            List<DigiDocException> e = verifyOcspOrCrl(sig, signedDoc, checkDate, bUseOcsp, timestampService,
    //                            crlService, canonicalizationService, verifyAlgorithm);
    //            if (!e.isEmpty()) errs.addAll(e);
    //        }
    //        
    //        if (signedDoc.countSignatures() == 0) {
    //            errs.add(new DigiDocException(DigiDocException.ERR_NOT_SIGNED, "This document is not signed!", null));
    //        }
    //        
    //        return errs;
    //    }
    
    /**
     * Verifies this signature
     * 
     * @param sdoc
     *            parent doc object
     * 
     * @param checkDate
     *            Date on which to check the signature validity
     * 
     * @param demandConfirmation
     *            true if you demand OCSP confirmation from every signature
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> verify(Signature signature, SignedDoc sdoc, boolean checkDate,
                    boolean demandConfirmation) {

        //        Date do1 = null, dt1 = null, dt2 = null;
        List<DigiDocException> errs = new ArrayList<DigiDocException>();
        
        initProvider();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying signature: " + signature.getId() + " profile: " + signature.getProfile());
        }

        // check the DataFile digests
        for (int i = 0; i < sdoc.countDataFiles(); i++) {
            DataFile df = sdoc.getDataFile(i);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verifying DF: " + df.getId() + " file: " + df.getFileName());
            }

            Reference ref = signature.getSignedInfo().getReferenceForDataFile(df);
            
            if (ref != null && ref.getDigestAlgorithm() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) && // check digest type
                            ref.getDigestAlgorithm().equals(SignedDoc.SHA1_DIGEST_ALGORITHM)) {
                errs.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, DIG_TYPE_WARNING, null));
                if (LOG.isInfoEnabled()) {
                    LOG.info("DataFile: " + df.getId() + " has weak digest type: " + ref.getDigestAlgorithm());
                }
            }
            if (ref != null) {
                List<DigiDocException> e = verifyDataFileHash(df, ref);
                if (!e.isEmpty()) {
                    errs.addAll(e);
                }
            } else {
                errs.add(new DigiDocException(DigiDocException.ERR_VERIFY, "Missing Reference for file: "
                                + df.getFileName(), null));
            }
        }
        
        // verify <SignedProperties>
        if (!sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
            List<DigiDocException> e = verifySignedPropretiesHash(signature);
            if (!e.isEmpty()) {
                errs.addAll(e);
            }
        }
        
        List<DigiDocException> e = verifySignatureValue(sdoc, signature);
        if (!e.isEmpty()) {
            errs.addAll(e);
        }
        
        // verify signers cert...
        // check the certs validity dates
        e = verifySigningTime(signature);
        if (!e.isEmpty()) {
            errs.addAll(e);
        }
        
        // check certificates CA
        e = verifySignersCerificate(signature);
        if (!e.isEmpty()) {
            errs.addAll(e);
        }
        
        // verify OCSP
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)
                        || sdoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)
                        || (signature.getProfile() != null && (signature.getProfile().equals(SignedDoc.BDOC_PROFILE_TM)
                                        || signature.getProfile().equals(SignedDoc.BDOC_PROFILE_TMA)
                                        || signature.getProfile().equals(SignedDoc.BDOC_PROFILE_TS) || signature
                                        .getProfile().equals(SignedDoc.BDOC_PROFILE_TSA)))) {
            e = verifySignatureOCSP(signature);
            if (!e.isEmpty()) {
                errs.addAll(e);
            }
        }
        
        // verify timestamps
        //        List<X509Certificate> tsaCerts = signature.findTSACerts();
        //        if (signature.getTimestamps() != null && signature.getTimestamps().size() > 0) {
        //            
        //            e = timestampService.verifySignaturesTimestamps(signature);
        //
        //            if (!e.isEmpty()) {
        //                errs.addAll(e);
        //            }
        //
        //            for (int i = 0; i < signature.getTimestamps().size(); i++) {
        //                TimestampInfo ts = (TimestampInfo) signature.getTimestamps().get(i);
        //                if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE) {
        //                    dt1 = ts.getTime();
        //                }
        //
        //                if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS) {
        //                    dt2 = ts.getTime();
        //                }
        //            }
        //            
        //            if (dt1 != null && dt2 != null) {
        //                dt1 = new Date(dt1.getTime() - (this.maxTSATimeErrSecs * 1000));
        //                dt2 = new Date(dt2.getTime() + (this.maxTSATimeErrSecs * 1000));
        //                
        //                if (dt2.before(dt1)) {
        //                    errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
        //                                    "SignAndRefsTimeStamp is before SignatureTimeStamp", null));
        //                }
        //                
        //                if (do1.before(dt1) || do1.after(dt2)) {
        //                    errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
        //                                    "OCSP time is not between SignAndRefsTimeStamp and SignatureTimeStamp", null));
        //                }
        //            }
        //
        //        }
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
        if (ex != null) {
            errs.add(ex);
        }

        List<DigiDocException> e = signature.getSignedInfo().validate();
        if (!e.isEmpty()) {
            errs.addAll(e);
        }
        
        if (signature.getSignatureValue() != null) {
            e = signature.getSignatureValue().validate();
            if (!e.isEmpty()) {
                errs.addAll(e);
            }
        }

        e = signature.getKeyInfo().validate();
        if (!e.isEmpty()) {
            errs.addAll(e);
        }
        
        if (signature.getSignedProperties() != null) {
            e = signature.getSignedProperties().validate();
            if (!e.isEmpty()) {
                errs.addAll(e);
            }
        }

        if (signature.getUnsignedProperties() != null) {
            e = signature.getUnsignedProperties().validate();
            if (!e.isEmpty()) {
                errs.addAll(e);
            }
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
    //    public List<DigiDocException> verifyOcspOrCrl(Signature signature, SignedDoc sdoc, boolean checkDate,
    //                    boolean bUseOcsp, TimestampService timestampService, CRLService crlService,
    //                    CanonicalizationService canonicalizationService) {
    //        Date do1 = null, dt1 = null, dt2 = null;
    //        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
    //        // check the DataFile digests
    //        for (int i = 0; i < sdoc.countDataFiles(); i++) {
    //            DataFile df = sdoc.getDataFile(i);
    //            Reference ref = signature.getSignedInfo().getReferenceForDataFile(df);
    //            byte[] dfDig = null;
    //            try {
    //                dfDig = df.getDigest();
    //            } catch (DigiDocException ex) {
    //                errs.add(ex);
    //            }
    //            if (ref != null) {
    //                if (!DDUtils.compareDigests(ref.getDigestValue(), dfDig)) {
    //                    errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE, "Bad digest for DataFile: "
    //                                    + df.getId(), null));
    //                }
    //            } else {
    //                errs.add(new DigiDocException(DigiDocException.ERR_DATA_FILE_NOT_SIGNED,
    //                                "No Reference element for DataFile: " + df.getId(), null));
    //            }
    //            // if this is a detatched file and the file referred by this entry actually exists, then go and check it's digest. 
    //            // If the datafile doesn't exist the just trust whatever is in the XML
    //            if (df.getContentType().equals(DataFile.CONTENT_DETATCHED)) {
    //                File fTest = new File(df.getFileName());
    //                if (fTest.canRead()) {
    //                    byte[] realDigest = null;
    //                    byte[] detDigest = null;
    //                    try {
    //                        realDigest = df.calculateDetatchedFileDigest();
    //                        detDigest = df.getDigestValue();
    //                    } catch (DigiDocException ex) {
    //                        errs.add(ex);
    //                    }
    //                    if (!DDUtils.compareDigests(detDigest, realDigest)) {
    //                        errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE,
    //                                        "Bad digest for detatched file: " + df.getFileName(), null));
    //                    }
    //                }
    //            }
    //        }
    //        // check signed properties digest
    //        Reference ref2 = signature.getSignedInfo().getReferenceForSignedProperties(signature.getSignedProperties());
    //        if (ref2 != null) {
    //            byte[] spDig = null;
    //            try {
    //                spDig = signature.getSignedProperties().calculateDigest();
    //            } catch (DigiDocException ex) {
    //                errs.add(ex);
    //            }
    //            if (!DDUtils.compareDigests(ref2.getDigestValue(), spDig)) {
    //                errs.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE, "Bad digest for SignedProperties: "
    //                                + signature.getSignedProperties().getId(), null));
    //            }
    //        } else {
    //            errs.add(new DigiDocException(DigiDocException.ERR_SIG_PROP_NOT_SIGNED,
    //                            "No Reference element for SignedProperties: " + signature.getSignedProperties().getId(),
    //                            null));
    //        }
    //        // verify signature value
    //        try {
    //            byte[] dig = signature.getSignedInfo().calculateDigest(canonicalizationService);
    //            
    //            if (sdoc != null && sdoc.getFormat().equals(SignedDoc.FORMAT_XADES)) {
    //                DigiDocXmlGenerator xmlGenerator = new DigiDocXmlGenerator(sdoc);
    //                byte[] xml = xmlGenerator.signedInfoToXML(signature, signature.getSignedInfo());
    //                if (LOG.isDebugEnabled()) {
    //                    LOG.debug("Verify xml:\n---\n" + new String(xml) + "\n---\n");
    //                }
    //                verify(xml, signature.getSignatureValue().getValue(), signature.getKeyInfo().getSignersCertificate(),
    //                                true, signature.getSignedInfo().getSignatureMethod());
    //                
    //            } else {
    //                verify(dig, signature.getSignatureValue().getValue(), signature.getKeyInfo().getSignersCertificate(),
    //                                false, signature.getSignedInfo().getSignatureMethod());
    //            }
    //        } catch (DigiDocException ex) {
    //            errs.add(ex);
    //            System.out.println("BAD DIGEST");
    //        }
    //        // verify signers cert...
    //        // check the certs validity dates
    //        try {
    //            if (checkDate)
    //                signature.getKeyInfo().getSignersCertificate()
    //                                .checkValidity(signature.getSignedProperties().getSigningTime());
    //        } catch (Exception ex) {
    //            errs.add(new DigiDocException(DigiDocException.ERR_CERT_EXPIRED, "Signers certificate has expired!", null));
    //        }
    //        // check certificates CA
    //        try {
    //            caService.verifyCertificate(signature.getKeyInfo().getSignersCertificate());
    //        } catch (DigiDocException ex) {
    //            errs.add(ex);
    //        }
    //        // switch OCSP or CRL verification
    //        if (bUseOcsp) { // use OCSP
    //            // check confirmation
    //            if (signature.getUnsignedProperties() != null) {
    //                List<DigiDocException> e = verify(signature.getUnsignedProperties(), sdoc);
    //                if (!e.isEmpty()) errs.addAll(e);
    //            } else { // not OCSP confirmation
    //                errs.add(new DigiDocException(DigiDocException.ERR_NO_CONFIRMATION,
    //                                "Signature has no OCSP confirmation!", null));
    //            }
    //            // verify timestamps
    //            List<X509Certificate> tsaCerts = signature.findTSACerts();
    //            if (signature.getTimestamps().size() > 0) {
    //                List<DigiDocException> e = timestampService.verifySignaturesTimestamps(signature);
    //                if (!e.isEmpty()) errs.addAll(e);
    //                for (int i = 0; i < signature.getTimestamps().size(); i++) {
    //                    TimestampInfo ts = (TimestampInfo) signature.getTimestamps().get(i);
    //                    if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE) dt1 = ts.getTime();
    //                    if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS) dt2 = ts.getTime();
    //                }
    //
    //                dt1 = new Date(dt1.getTime() - (this.maxTSATimeErrSecs * 1000));
    //                dt2 = new Date(dt2.getTime() + (this.maxTSATimeErrSecs * 1000));
    //
    //                if (dt2.before(dt1))
    //                    errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
    //                                    "SignAndRefsTimeStamp is before SignatureTimeStamp", null));
    //                if (do1.before(dt1) || do1.after(dt2))
    //                    errs.add(new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
    //                                    "OCSP time is not between SignAndRefsTimeStamp and SignatureTimeStamp", null));
    //            }
    //        } else {
    //            try {
    //                crlService.checkCertificate(signature.getKeyInfo().getSignersCertificate(), new Date());
    //            } catch (DigiDocException ex) {
    //                errs.add(ex);
    //            }
    //        }
    //        return errs;
    //    }
    
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
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Responders cert: " + cert.getSerialNumber() + " - " + cert.getSubjectDN().getName()
                            + " complete cert refs nr: "
                            + unsignedProperties.getCompleteCertificateRefs().getCertSerial() + " - "
                            + unsignedProperties.getCompleteCertificateRefs().getCertIssuer());
        }

        if (cert == null) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "No notarys certificate!", null));
            return errs;
        }
        
        if (cert != null
                        && !cert.getSerialNumber().equals(
                                        unsignedProperties.getCompleteCertificateRefs().getCertSerial())
                        && !unsignedProperties.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                        && !unsignedProperties.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_XADES)) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "Wrong notarys certificate: "
                            + cert.getSerialNumber() + " ref: "
                            + unsignedProperties.getCompleteCertificateRefs().getCertSerial(), null));
        }
        
        // verify notary certs digest using CompleteCertificateRefs
        try {
            if (!unsignedProperties.getSignature().getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                            && !unsignedProperties.getSignature().getSignedDoc().getFormat()
                                            .equals(SignedDoc.FORMAT_XADES)) {
                byte[] digest = DDUtils.digestOfType(cert.getEncoded(), (unsignedProperties.getSignature()
                                .getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                                : DDUtils.SHA1_DIGEST_TYPE));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Not cert calc hash: "
                                    + Base64Util.encode(digest, 0)
                                    + " cert-ref hash: "
                                    + Base64Util.encode(unsignedProperties.getCompleteCertificateRefs()
                                                    .getCertDigestValue(), 0));
                }
                if (!DDUtils.compareDigests(digest, unsignedProperties.getCompleteCertificateRefs()
                                .getCertDigestValue())) {
                    errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                                    "Notary certificates digest doesn't match!", null));
                    LOG.error("Notary certificates digest doesn't match!");
                }
            }
        } catch (Exception ex) {
            errs.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                            "Error calculating notary certificate digest!", null));
        }
        
        // verify notarys digest using CompleteRevocationRefs
        for (int i = 0; i < unsignedProperties.countNotaries(); i++) {
            Notary not = unsignedProperties.getNotaryById(i);
            byte[] ocspData = not.getOcspResponseData();
            if (LOG.isDebugEnabled()) {
                LOG.debug("OCSP value: " + not.getId() + " data: " + ((ocspData != null) ? ocspData.length : 0)
                                + " bytes");
            }
            if (ocspData == null || ocspData.length == 0) {
                errs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "OCSP value is empty!", null));
                continue;
            }
            OcspRef orf = unsignedProperties.getCompleteRevocationRefs().getOcspRefByUri("#" + not.getId());
            if (LOG.isDebugEnabled()) LOG.debug("OCSP ref: " + ((orf != null) ? orf.getUri() : "NULL"));
            if (orf == null) {
                errs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "No OCSP ref for uri: #"
                                + not.getId(), null));
                continue;
            }
            
            byte[] digest1 = DDUtils.digestOfType(ocspData, (unsignedProperties.getSignature().getSignedDoc()
                            .getFormat().equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                            : DDUtils.SHA1_DIGEST_TYPE));
            byte[] digest2 = orf.getDigestValue();
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Check ocsp: " + not.getId() + " calc hash: " + Base64Util.encode(digest1, 0)
                                + " refs-hash: " + Base64Util.encode(digest2, 0));
            }
            if (!DDUtils.compareDigests(digest1, digest2)) {
                errs.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "Notarys digest doesn't match!", null));
                LOG.error("Notarys digest doesn't match!");
            }
        }
        
        // verify notary status
        try {
            for (int i = 0; i < unsignedProperties.countNotaries(); i++) {
                Notary not = unsignedProperties.getNotaryById(i);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Verify notray: " + not.getId() + " ocsp: "
                                    + ((not.getOcspResponseData() != null) ? not.getOcspResponseData().length : 0)
                                    + " responder: " + not.getResponderId());
                }
                notaryService.parseAndVerifyResponse(unsignedProperties.getSignature(), unsignedProperties.getNotary());
            }
        } catch (DigiDocException ex) {
            errs.add(ex);
        }
        
        return errs;
    }
    
    /**
     * Verifies the siganture
     * 
     * @param digest input data digest
     * @param signature signature value
     * @param cert certificate to be used on verify
     * @param bSoftCert use Sun verificateion api instead
     * @return true if signature verifies
     */
    public boolean verify(byte[] digest, byte[] signature, X509Certificate cert, boolean bSoftCert, String sigMethod)
                    throws DigiDocException {
        boolean rc = false;
        try {

            if (cert == null) {
                throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid or missing signers cert!", null);
            }

            if (bSoftCert) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Verify xml:\n---\n" + new String(digest) + "\n---\n method: " + sigMethod);
                }
                java.security.Signature sig = null;
                if (sigMethod.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD)) {
                    sig = java.security.Signature.getInstance("SHA1withRSA", "BC");
                } else if (sigMethod.equals(SignedDoc.RSA_SHA224_SIGNATURE_METHOD)) {
                    sig = java.security.Signature.getInstance("SHA224withRSA", "BC");
                } else if (sigMethod.equals(SignedDoc.RSA_SHA256_SIGNATURE_METHOD)) {
                    sig = java.security.Signature.getInstance("SHA256withRSA", "BC");
                } else {
                    throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid signature method!", null);
                }
                if (sig == null) {
                    throw new DigiDocException(DigiDocException.ERR_VERIFY, "Signature method: " + sigMethod
                                    + " not provided!", null);
                }
                sig.initVerify((java.security.interfaces.RSAPublicKey) cert.getPublicKey());
                sig.update(digest);
                rc = sig.verify(signature);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Verify sig: " + signature.length + " bytes, alg: " + DIGIDOC_VERIFY_ALGORITHM
                                    + " sig-alg: " + sigMethod);
                }
                Cipher cryptoEngine = Cipher.getInstance(DIGIDOC_VERIFY_ALGORITHM, "BC");
                cryptoEngine.init(Cipher.DECRYPT_MODE, cert);
                byte[] decdig = null;
                try {
                    decdig = cryptoEngine.doFinal(signature);
                } catch (java.lang.ArrayIndexOutOfBoundsException ex2) {
                    LOG.error("Invalid signature value. Signers cert and signature value don't match! - " + ex2);
                    throw new DigiDocException(DigiDocException.ERR_VERIFY,
                                    "Invalid signature value! Signers cert and signature value don't match!", ex2);
                }
                String digType2 = DDUtils.sigMeth2Type(sigMethod);
                String digType1 = DDUtils.findDigType(decdig);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Decrypted digest: \'" + ConvertUtils.bin2hex(decdig) + "\' len: " + decdig.length
                                    + " has-pref: " + digType1 + " must-have: " + digType2 + " alg: " + sigMethod);
                }
                if ((digType1 == null) || (digType2 != null && digType1 != null && !digType2.equals(digType1))) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signature asn.1 prefix: " + digType1 + " does not match: " + digType2);
                    }
                    throw new DigiDocException(DigiDocException.ERR_VERIFY, "Signature asn.1 prefix: " + digType1
                                    + " does not match: " + digType2, null);
                }
                byte[] cdigest = null;
                cdigest = DDUtils.removePrefix(decdig);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signed digest: \'" + ((cdigest != null) ? ConvertUtils.bin2hex(cdigest) : "NULL")
                                    + "\' calc-digest: \'" + ConvertUtils.bin2hex(digest) + "\'");
                }
                if (decdig != null && cdigest != null && decdig.length == cdigest.length) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signature value decrypted len: " + decdig.length + " missing ASN.1 structure prefix");
                    }
                    throw new DigiDocException(DigiDocException.ERR_VERIFY,
                                    "Invalid signature value! Signature value decrypted len: " + decdig.length
                                                    + " missing ASN.1 structure prefix", null);
                }
                rc = DDUtils.compareDigests(digest, cdigest);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Result: " + rc);
            }
            if (!rc) {
                throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid signature value!", null);
            }
        } catch (DigiDocException ex) {
            throw ex; // pass it on, but check other exceptions
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_VERIFY);
        }
        return rc;
    }
    
    private List<DigiDocException> verifyDataFileHash(DataFile df, Reference ref) {
        List<DigiDocException> errors = new ArrayList<DigiDocException>();

        if (df != null) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Check digest for DF: " + df.getId() + " ref: " + ((ref != null) ? ref.getUri() : "NULL"));
            }
            
            String sDigType = DDUtils.digAlg2Type(ref.getDigestAlgorithm());
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Check digest for DF: " + df.getId() + " type: " + sDigType);
            }
            
            byte[] dfDig = null;
            try {
                dfDig = df.getDigestValueOfType(sDigType);
            } catch (DigiDocException ex) {
                errors.add(ex);
                LOG.error("Error calculating hash for df: " + df.getId() + " - " + ex);
                ex.printStackTrace();
                if (ex.getNestedException() != null) {
                    ex.getNestedException().printStackTrace();
                }
            }
            
            if (ref != null) {
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Compare digest: "
                                    + ((dfDig != null) ? Base64Util.encode(dfDig, 0) : "NONE")
                                    + " alt digest: "
                                    + ((df.getAltDigest() != null) ? Base64Util.encode(df.getAltDigest(), 0) : "NONE")
                                    + " to: "
                                    + ((ref.getDigestValue() != null) ? Base64Util.encode(ref.getDigestValue())
                                                    : "NONE"));
                }
                
                DigiDocException exd = null;
                if (!DDUtils.compareDigests(ref.getDigestValue(), dfDig)) {
                    exd = new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE, "Bad digest for DataFile: "
                                    + df.getId(), null);
                    errors.add(exd);
                    LOG.error("BAD DIGEST for DF: " + df.getId());
                }
                if (!errors.isEmpty() && df.getAltDigest() != null) {
                    if (DDUtils.compareDigests(ref.getDigestValue(), ref.getDigestValue())) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("DF: " + df.getId() + " alternate digest matches!");
                        }
                        LOG.error("GOOD ALT DIGEST for DF: " + df.getId());
                        if (exd != null) {
                            errors.remove(exd);
                        }
                        ref.getSignedInfo().getSignature().setAltDigestMatch(true);
                    }
                } else if (LOG.isDebugEnabled()) {
                    LOG.debug("GOOD DIGEST");
                }
            } else {
                LOG.error("No Reference");
                errors.add(new DigiDocException(DigiDocException.ERR_DATA_FILE_NOT_SIGNED,
                                "No Reference element for DataFile: " + df.getId(), null));
            }
        } else {
            LOG.error("Invalid data-file");
        }
        return errors;
    }
    
    private List<DigiDocException> verifySignedPropretiesHash(Signature sig) {
        List<DigiDocException> errors = new ArrayList<DigiDocException>();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying signed-props of: " + sig.getId());
        }
        
        SignedProperties sp = sig.getSignedProperties();
        
        if (sp != null) {
            Reference ref2 = sig.getSignedInfo().getReferenceForSignedProperties(sp);
            if (sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) && ref2.getDigestAlgorithm() != null
                            && ref2.getDigestAlgorithm().equals(SignedDoc.SHA1_DIGEST_ALGORITHM)) {// check digest type
                errors.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, DIG_TYPE_WARNING, null));
                if (LOG.isInfoEnabled()) {
                    LOG.info("SignedProperties for signature: " + sig.getId() + " has weak digest type: "
                                    + ref2.getDigestAlgorithm());
                }
            }
            if (ref2 != null) {
                byte[] spDig = null;
                try {
                    spDig = DDUtils.calculateDigest(sp, canonicalizationService);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("SignedProp real digest: " + Base64Util.encode(spDig, 0));
                    }
                } catch (DigiDocException ex) {
                    errors.add(ex);
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Compare it to: "
                                    + ((ref2.getDigestValue() != null) ? Base64Util.encode(ref2.getDigestValue(), 0)
                                                    : null));
                }
                if (!DDUtils.compareDigests(ref2.getDigestValue(), spDig)) {
                    errors.add(new DigiDocException(DigiDocException.ERR_DIGEST_COMPARE,
                                    "Bad digest for SignedProperties: " + sp.getId(), null));
                    LOG.error("BAD DIGEST for sig-prop");
                } else if (LOG.isDebugEnabled()) {
                    LOG.debug("GOOD DIGEST");
                }
            } else {
                LOG.error("No Reference element for SignedProperties: " + sp.getId());
                errors.add(new DigiDocException(DigiDocException.ERR_SIG_PROP_NOT_SIGNED,
                                "No Reference element for SignedProperties: " + sp.getId(), null));
            }
            
        } else {
            LOG.error("No Reference element for SignedProperties: " + sp.getId());
            errors.add(new DigiDocException(DigiDocException.ERR_SIG_PROP_NOT_SIGNED,
                            "No Reference element for SignedProperties: " + sp.getId(), null));
        }
        return errors;
    }
    
    public List<DigiDocException> verifySignatureValue(SignedDoc sdoc, Signature sig) {
        List<DigiDocException> errors = new ArrayList<DigiDocException>();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying signature value of: " + sig.getId());
        }
        // verify signature value
        try {
            byte[] dig = DDUtils.calculateDigest(sig.getSignedInfo(), canonicalizationService);
            if (LOG.isDebugEnabled()) {
                LOG.debug("SignedInfo real digest: " + Base64Util.encode(dig, 0) + " hex: " + ConvertUtils.bin2hex(dig));
            }
            if (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) && // check digest type
                            sig.getSignedInfo().getSignatureMethod().equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD)) {
                errors.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, DIG_TYPE_WARNING, null));
                if (LOG.isInfoEnabled()) {
                    LOG.info("Signature: " + sig.getId() + " has weak signature method: "
                                    + sig.getSignedInfo().getSignatureMethod());
                }
            }
            if (sig.getSignatureValue() != null && sig.getSignatureValue().getValue() != null) {
                if (sdoc != null && sdoc.getFormat().equals(SignedDoc.FORMAT_XADES)) {
                    DigiDocXmlGenerator genFac = new DigiDocXmlGenerator(sdoc);
                    byte[] xml = genFac.signedInfoToXML(sig, sig.getSignedInfo());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Verify xml:\n---\n" + new String(xml) + "\n---\n");
                    }
                    verify(xml, sig.getSignatureValue().getValue(), sig.getKeyInfo().getSignersCertificate(), true, sig
                                    .getSignedInfo().getSignatureMethod());
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Verify sig: " + ConvertUtils.bin2hex(sig.getSignatureValue().getValue()));
                        verify(dig, sig.getSignatureValue().getValue(), sig.getKeyInfo().getSignersCertificate(),
                                        false, sig.getSignedInfo().getSignatureMethod());
                    }
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("GOOD DIGEST");
                }
            } else {
                LOG.error("Missing signature value!");
                errors.add(new DigiDocException(DigiDocException.ERR_SIGNATURE_VALUE_VALUE, "Missing signature value!",
                                null));
            }
        } catch (DigiDocException ex) {
            errors.add(ex);
            LOG.error("BAD DIGEST for sig-inf: " + sig.getId() + " - " + ex.toString());
            LOG.error("TRACE: " + ConvertUtils.getTrace(ex));
            LOG.error("sig-val-len: "
                            + ((sig.getSignatureValue() != null && sig.getSignatureValue().getValue() != null) ? sig
                                            .getSignatureValue().getValue().length : 0));
            LOG.error("signer: "
                            + ((sig.getKeyInfo() != null && sig.getKeyInfo().getSignersCertificate() != null) ? sig
                                            .getKeyInfo().getSignersCertificate().getSubjectDN().getName() : "NULL"));
        }
        return errors;
    }
    
    public List<DigiDocException> verifySigningTime(Signature sig) {
        List<DigiDocException> errors = new ArrayList<DigiDocException>();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying signing time signature: " + sig.getId());
        }
        
        try {
            sig.getKeyInfo().getSignersCertificate().checkValidity(sig.getSignedProperties().getSigningTime());
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signers cert: "
                                + DDUtils.getCommonName(sig.getKeyInfo().getSignersCertificate().getSubjectDN()
                                                .getName())
                                + " was valid on: "
                                + ConvertUtils.date2string(sig.getSignedProperties().getSigningTime(),
                                                sig.getSignedDoc()));
            }
        } catch (Exception ex) {
            LOG.error("Signers certificate has expired for: " + sig.getId());
            errors.add(new DigiDocException(DigiDocException.ERR_CERT_EXPIRED, "Signers certificate has expired!", null));
        }
        return errors;
    }
    
    public List<DigiDocException> verifySignersCerificate(Signature sig) {
        List<DigiDocException> errors = new ArrayList<DigiDocException>();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying CA of signature: " + sig.getId());
        }
        try {
            if (sig.getKeyInfo().getSignersCertificate() == null) {
                errors.add(new DigiDocException(DigiDocException.ERR_SIGNERS_CERT, "Signers cert missing!", null));
                return errors;
            }
            X509Certificate caCert = trustService.findCaForCert(sig.getKeyInfo().getSignersCertificate());
            X509Certificate cert = sig.getKeyInfo().getSignersCertificate();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Check signer: " + cert.getSubjectDN().getName() + " issued by: "
                                + cert.getIssuerDN().getName() + " by CA: "
                                + ((caCert != null) ? caCert.getSubjectDN().getName() : "NOT FOUND"));
            }
            if (caCert != null) {
                verifyCertificate(cert, caCert);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer: "
                                    + DDUtils.getCommonName(sig.getKeyInfo().getSignersCertificate().getSubjectDN()
                                                    .getName())
                                    + " is issued by trusted CA: "
                                    + ((caCert != null) ? DDUtils.getCommonName(caCert.getSubjectDN().getName())
                                                    : "NULL"));
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("CA not found for: " + DDUtils.getCommonName(cert.getSubjectDN().getName()));
                }
                errors.add(new DigiDocException(DigiDocException.ERR_SIGNERS_CERT,
                                "Signers cert not trusted, missing CA cert!", null));
            }
            if (!DDUtils.isSignatureKey(cert)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signers cert does not have non-repudiation bit set!");
                }
                errors.add(new DigiDocException(DigiDocException.ERR_SIGNERS_CERT_NONREPUD,
                                "Signers cert does not have non-repudiation bit set!", null));
            }
        } catch (DigiDocException ex) {
            LOG.error("Signers certificate not trusted for: " + sig.getId());
            errors.add(ex);
        }
        return errors;
    }
    
    public boolean verifyCertificate(X509Certificate cert, X509Certificate caCert) throws DigiDocException {
        boolean rc = false;
        try {
            if (caCert != null) {
                cert.verify(caCert.getPublicKey());
                rc = true;
            }
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UNKNOWN_CA_CERT);
        }
        return rc;
    }
    
    public List<DigiDocException> verifySignatureOCSP(Signature sig) {
        List<DigiDocException> errors = new ArrayList<DigiDocException>();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying OCSP for signature: " + sig.getId());
        }
        try {
            if (sig.getUnsignedProperties() != null && sig.getUnsignedProperties().countNotaries() > 0) {
                CertValue cvOcsp = sig.getCertValueOfType(CertValue.CERTVAL_TYPE_RESPONDER);
                CertID cidOcsp = sig.getCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
                X509Certificate rCert = null;
                String sIssuer = null;
                BigInteger sSerial = null;
                byte[] cHash = null;
                if (cvOcsp != null) {
                    rCert = cvOcsp.getCert();
                }
                if (cidOcsp != null) {
                    sIssuer = cidOcsp.getIssuer();
                    sSerial = cidOcsp.getSerial();
                    cHash = cidOcsp.getDigestValue();
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Responders cert: " + ((rCert != null) ? rCert.getSerialNumber().toString() : "NULL")
                                    + " - " + ((rCert != null) ? rCert.getSubjectDN().getName() : "NULL")
                                    + " complete cert refs nr: " + sSerial + " - " + sIssuer);
                }
                if (rCert == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No ocsp responder cert for: " + sig.getId());
                    }
                    errors.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "No notarys certificate!",
                                    null));
                    return errors;
                }
                if (!rCert.getSerialNumber().equals(sSerial)
                                && !sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                                && !sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_XADES)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Wrong notarys certificate: " + rCert.getSerialNumber() + " ref: " + sSerial);
                    }
                    errors.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT, "Wrong notarys certificate: "
                                    + rCert.getSerialNumber() + " ref: " + sSerial, null));
                }
                // verify notary certs digest using CompleteCertificateRefs
                try {
                    if (!sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC)
                                    && !sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_XADES)) {
                        byte[] digest = DDUtils.digestOfType(rCert.getEncoded(), (sig.getSignedDoc().getFormat()
                                        .equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                                        : DDUtils.SHA1_DIGEST_TYPE));
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Not cert calc hash: "
                                            + Base64Util.encode(digest, 0)
                                            + " cert-ref hash: "
                                            + Base64Util.encode(sig.getUnsignedProperties()
                                                            .getCompleteCertificateRefs().getCertDigestValue(), 0));
                        }
                        if (!DDUtils.compareDigests(digest, sig.getUnsignedProperties().getCompleteCertificateRefs()
                                        .getCertDigestValue())) {
                            errors.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                                            "Notary certificates digest doesn't match!", null));
                            LOG.error("Notary certificates digest doesn't match!");
                        }
                        if (sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) && // check digest type
                                        sig.getUnsignedProperties().getCompleteCertificateRefs()
                                                        .getCertDigestAlgorithm()
                                                        .equals(SignedDoc.SHA1_DIGEST_ALGORITHM)) {
                            errors.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, DIG_TYPE_WARNING, null));
                            if (LOG.isInfoEnabled()) {
                                LOG.info("CompleteCertificateRefs for signature: "
                                                + sig.getId()
                                                + " has weak digest type: "
                                                + sig.getUnsignedProperties().getCompleteCertificateRefs()
                                                                .getCertDigestAlgorithm());
                            }
                        }
                    }
                    // TODO: in bdoc verify responders ca hash - verify all hashes in certrefs
                    
                } catch (Exception ex) {
                    errors.add(new DigiDocException(DigiDocException.ERR_RESPONDERS_CERT,
                                    "Error calculating notary certificate digest!", null));
                }
                
                // verify notarys digest using CompleteRevocationRefs
                for (int i = 0; i < sig.getUnsignedProperties().countNotaries(); i++) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signature: " + sig.getId() + " not: " + i + " notaries: "
                                        + sig.getUnsignedProperties().countNotaries());
                    }
                    Notary not = sig.getUnsignedProperties().getNotaryById(i);
                    if (i > 0) {
                        LOG.error("Currently supports only one OCSP. Invalid ocsp: " + not.getId());
                        errors.add(new DigiDocException(DigiDocException.ERR_OCSP_VERIFY,
                                        "Currently supports only one OCSP. Invalid ocsp: " + not.getId(), null));
                    }
                    byte[] ocspData = not.getOcspResponseData();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("OCSP value: " + not.getId() + " data: " + ((ocspData != null) ? ocspData.length : 0)
                                        + " bytes");
                    }
                    if (ocspData == null || ocspData.length == 0) {
                        errors.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "OCSP value is empty!",
                                        null));
                        continue;
                    }
                    OcspRef orf = sig.getUnsignedProperties().getCompleteRevocationRefs()
                                    .getOcspRefByUri("#" + not.getId());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("OCSP ref: " + ((orf != null) ? orf.getUri() : "NULL"));
                    }
                    if (orf == null) {
                        errors.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST, "No OCSP ref for uri: #"
                                        + not.getId(), null));
                        continue;
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("OCSP data len: " + ocspData.length);
                    }
                    byte[] digest1 = DDUtils
                                    .digestOfType(ocspData,
                                                    ((sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) && (orf
                                                                    .getDigestAlgorithm()
                                                                    .equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1) || orf
                                                                    .getDigestAlgorithm()
                                                                    .equals(SignedDoc.SHA256_DIGEST_ALGORITHM_2))) ? DDUtils.SHA256_DIGEST_TYPE
                                                                    : DDUtils.SHA1_DIGEST_TYPE));
                    byte[] digest2 = orf.getDigestValue();
                    
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Check ocsp: " + not.getId() + " calc hash: " + Base64Util.encode(digest1, 0)
                                        + " refs-hash: " + Base64Util.encode(digest2, 0));
                    }
                    if (!sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_SK_XML)
                                    && !DDUtils.compareDigests(digest1, digest2)) {
                        errors.add(new DigiDocException(DigiDocException.ERR_NOTARY_DIGEST,
                                        "Notarys digest doesn't match!", null));
                        LOG.error("Notarys digest doesn't match!");
                    }
                    if (sig.getSignedDoc().getFormat().equals(SignedDoc.FORMAT_BDOC) && // check digest type
                                    orf.getDigestAlgorithm().equals(SignedDoc.SHA1_DIGEST_ALGORITHM)) {
                        errors.add(new DigiDocException(DigiDocException.WARN_WEAK_DIGEST, DIG_TYPE_WARNING, null));
                        if (LOG.isInfoEnabled()) {
                            LOG.info("CompleteRevocationRefs for signature: " + sig.getId() + " has weak digest type: "
                                            + orf.getDigestAlgorithm());
                        }
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Check ocsp: "
                                        + not.getId()
                                        + " prodAt: "
                                        + ((not.getProducedAt() != null) ? ConvertUtils.date2string(
                                                        not.getProducedAt(), sig.getSignedDoc()) : "NULL")
                                        + " orf prodAt: "
                                        + ((orf.getProducedAt() != null) ? ConvertUtils.date2string(
                                                        orf.getProducedAt(), sig.getSignedDoc()) : "NULL"));
                    }
                    if (not.getProducedAt() != null
                                    && orf.getProducedAt() != null
                                    && !ConvertUtils.date2string(not.getProducedAt(), sig.getSignedDoc()).equals(
                                                    ConvertUtils.date2string(orf.getProducedAt(), sig.getSignedDoc()))) {
                        LOG.error("Notary: "
                                        + not.getId()
                                        + " producedAt: "
                                        + ((not.getProducedAt() != null) ? ConvertUtils.date2string(
                                                        not.getProducedAt(), sig.getSignedDoc()) : "NULL")
                                        + " does not match OcpsRef-s producedAt: "
                                        + ((orf.getProducedAt() != null) ? ConvertUtils.date2string(
                                                        orf.getProducedAt(), sig.getSignedDoc()) : "NULL"));
                        errors.add(new DigiDocException(DigiDocException.ERR_OCSP_VERIFY, "Notary: "
                                        + not.getId()
                                        + " producedAt: "
                                        + ((not.getProducedAt() != null) ? ConvertUtils.date2string(
                                                        not.getProducedAt(), sig.getSignedDoc()) : "NULL")
                                        + " does not match OcpsRef-s producedAt: "
                                        + ((orf.getProducedAt() != null) ? ConvertUtils.date2string(
                                                        orf.getProducedAt(), sig.getSignedDoc()) : "NULL"), null));
                    }
                }
                // verify notary status
                try {
                    for (int i = 0; i < sig.getUnsignedProperties().countNotaries(); i++) {
                        Notary not = sig.getUnsignedProperties().getNotaryById(i);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Verify notary: "
                                            + not.getId()
                                            + " ocsp: "
                                            + ((not.getOcspResponseData() != null) ? not.getOcspResponseData().length
                                                            : 0) + " responder: " + not.getResponderId());
                        }
                        notaryService.parseAndVerifyResponse(sig, not);
                    }
                } catch (DigiDocException ex) {
                    errors.add(ex);
                }
                
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signature has no OCSP confirmation!");
                }
                errors.add(new DigiDocException(DigiDocException.ERR_NO_CONFIRMATION,
                                "Signature has no OCSP confirmation!", null));
            }
        } catch (Exception ex) {
            LOG.error("Failed to verify OCSP for: " + sig.getId());
            errors.add(new DigiDocException(DigiDocException.ERR_CERT_EXPIRED, "Failed to verify OCSP for: "
                            + sig.getId(), null));
        }
        return errors;
    }
}
