package ee.sk.digidoc.services;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampResponse;

import ee.sk.digidoc.CertID;
import ee.sk.digidoc.CertValue;
import ee.sk.digidoc.CompleteCertificateRefs;
import ee.sk.digidoc.CompleteRevocationRefs;
import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.IncludeInfo;
import ee.sk.digidoc.KeyInfo;
import ee.sk.digidoc.ManifestFileEntry;
import ee.sk.digidoc.Notary;
import ee.sk.digidoc.OcspRef;
import ee.sk.digidoc.Reference;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignatureProductionPlace;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.SignedInfo;
import ee.sk.digidoc.SignedProperties;
import ee.sk.digidoc.TimestampInfo;
import ee.sk.digidoc.UnsignedProperties;
import ee.sk.utils.Base64Util;
import ee.sk.utils.DDUtils;

/**
 * Factory class to handle generating signature elements according to
 * required signature type and version or in case of bdoc the profile
 * 
 * @author Veiko Sinivee
 */
public class DigiDocGenServiceImpl {
    
    private static Logger LOG = Logger.getLogger(DigiDocGenServiceImpl.class);
    
    private static final String DIGI_OID_LIVE_TEST = "1.3.6.1.4.1.10015.1.2";
    private static final String DIGI_OID_TEST_TEST = "1.3.6.1.4.1.10015.3.2";
    
    private static final String RMID_OID_TEST = "1.3.6.1.4.1.10015.3.3.1";
    private static final String ASUTUSE_OID_TEST = "1.3.6.1.4.1.10015.3.7.1";
    private static final String MID_OID_TEST = "1.3.6.1.4.1.10015.3.11.1";
    
    private TrustService trustService;
    private TimestampService timeStampService;
    private NotaryService notaryService;

    private boolean keyUsageCheck = true;
    private String tsaUrl = null;
    
    public void setKeyUsageCheck(boolean keyUsageCheck) {
        this.keyUsageCheck = keyUsageCheck;
    }
    
    public void setTsaUrl(String tsaUrl) {
        this.tsaUrl = tsaUrl;
    }
    
    public DigiDocGenServiceImpl(TrustService trustService, TimestampService timeStampService,
                    NotaryService notaryService) {
        this.trustService = trustService;
        this.timeStampService = timeStampService;
        this.notaryService = notaryService;
    }

    private static boolean certHasPolicy(X509Certificate cert, String sOid) {
        try {
            if (LOG.isDebugEnabled()) LOG.debug("Read cert policies: " + cert.getSerialNumber().toString());
            ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
            ASN1InputStream aIn = new ASN1InputStream(bIn);
            ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
            X509CertificateStructure obj = new X509CertificateStructure(seq);
            TBSCertificateStructure tbsCert = obj.getTBSCertificate();
            if (tbsCert.getVersion() == 3) {
                X509Extensions ext = tbsCert.getExtensions();
                if (ext != null) {
                    Enumeration en = ext.oids();
                    while (en.hasMoreElements()) {
                        DERObjectIdentifier oid = (DERObjectIdentifier) en.nextElement();
                        X509Extension extVal = ext.getExtension(oid);
                        ASN1OctetString oct = extVal.getValue();
                        ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));
                        //if (oid.equals(X509Extension.certificatePolicies)) { // bc 146 ja jdk 1.6 puhul - X509Extension.certificatePolicies
                        if (oid.equals(X509Extensions.CertificatePolicies)) { // bc 1.44 puhul - X509Extensions.CertificatePolicies
                            ASN1Sequence cp = (ASN1Sequence) extIn.readObject();
                            for (int i = 0; i != cp.size(); i++) {
                                PolicyInformation pol = PolicyInformation.getInstance(cp.getObjectAt(i));
                                DERObjectIdentifier dOid = pol.getPolicyIdentifier();
                                String soid2 = dOid.getId();
                                if (LOG.isDebugEnabled()) LOG.debug("Policy: " + soid2);
                                if (soid2.startsWith(sOid)) return true;
                            }
                        }
                    }
                }
                
            }
        } catch (Exception ex) {
            LOG.error("Error reading cert policies: " + ex);
        }
        return false;
    }
    
    private static boolean is2011Card(X509Certificate cert) {
        return ((cert != null) && ((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength() == 2048);
    }
    
    private static boolean isDigiIdCard(X509Certificate cert) {
        return ((cert != null) && (((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength() == 1024) && (certHasPolicy(
                        cert, DIGI_OID_LIVE_TEST)
                        || certHasPolicy(cert, DIGI_OID_TEST_TEST)
                        || certHasPolicy(cert, RMID_OID_TEST) || certHasPolicy(cert, ASUTUSE_OID_TEST) || certHasPolicy(
                            cert, MID_OID_TEST)));
    }
    
    private static boolean isPre2011IdCard(X509Certificate cert) {
        return ((cert != null) && (((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength() == 1024)
                        && !certHasPolicy(cert, DIGI_OID_LIVE_TEST) && !certHasPolicy(cert, DIGI_OID_TEST_TEST));
    }
    
    /**
     * Create new SignedDoc object
     * 
     * @param format - SK-XML, DIGIDOC-XML, BDOC
     * @param version - 1.0, 1.1, 1.2, 1.3, bdoc has only 1.0 and 1.1
     * @param profile - BES, T, C-L, TM, TS, TM-A, TS-A
     */
    public static SignedDoc createSignedDoc(String format, String version, String profile) throws DigiDocException {
        String ver = version;
        if (format != null && format.equals(SignedDoc.FORMAT_BDOC)) {
            if (profile != null
                            && (profile.equals(SignedDoc.BDOC_PROFILE_T) || profile.equals(SignedDoc.BDOC_PROFILE_CL)))
                ver = SignedDoc.BDOC_VERSION_1_1;
            else
                ver = SignedDoc.BDOC_VERSION_1_0;
            // if profile is not set then lookup default profile from config
            // if not set in config use TM as default
            if (profile == null || profile.trim().length() == 0) {
                profile = SignedDoc.BDOC_PROFILE_TM;
            }
        }
        if (format != null && (format.equals(SignedDoc.FORMAT_SK_XML) || format.equals(SignedDoc.FORMAT_DIGIDOC_XML))) {
            if (ver == null) {
                ver = SignedDoc.VERSION_1_3;
            }
            profile = SignedDoc.BDOC_PROFILE_TM; // in ddoc format we used only TM
        }
        if (LOG.isDebugEnabled()) LOG.debug("Creating digidoc: " + format + " / " + ver + " / " + profile);
        SignedDoc sdoc = new SignedDoc(format, ver);
        sdoc.setProfile(profile);
        return sdoc;
    }
    
    private static void registerCert(X509Certificate cert, int type, String id, Signature sig) throws DigiDocException {
        String sid = id;
        if (sid != null) sid = sid.replace(" ", "_");
        CertValue cval = new CertValue(sid, cert, type, sig);
        sig.addCertValue(cval);
        CertID cid = new CertID(sig, cert, type);
        sig.addCertID(cid);
        if (type != CertID.CERTID_TYPE_SIGNER) cid.setUri("#" + cval.getId());
    }
    
    /**
     * Adds a new uncomplete signature to signed doc
     * 
     * @param sdoc SignedDoc object
     * @param profile new signature profile. Use NULL for default
     * @param cert signers certificate
     * @param claimedRoles signers claimed roles
     * @param adr signers address
     * @param sId new signature id, Use NULL for default value
     * @param sSigMethod signature method uri - ddoc: SignedDoc.RSA_SHA1_SIGNATURE_METHOD, bdoc: depends on card type.
     *            Use null for default value
     * @param sDigType digest type (all other hashes but SignedInfo). Use null for default type
     * @return new Signature object
     */
    public Signature prepareXadesBES(SignedDoc sdoc, String profile, X509Certificate cert,
                    String[] claimedRoles, SignatureProductionPlace adr, String sId, String sSigMethod, String sDigType)
                    throws DigiDocException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Prepare signature in sdoc: " + sdoc.getFormat() + "/" + sdoc.getVersion() + "/"
                            + sdoc.getProfile() + " profile: " + profile + " signer: "
                            + ((cert != null) ? DDUtils.getCommonName(cert.getSubjectDN().getName()) : "unknown")
                            + " id " + sId);
        }
        // cannot proceed if cert has not been read
        if (cert == null) {
            LOG.error("Signers certificate missing during signature preparation!");
            throw new DigiDocException(DigiDocException.ERR_SIGNERS_CERT,
                            "Signers certificate missing during signature preparation!", null);
        }
        if (keyUsageCheck && !DDUtils.isSignatureKey(cert)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signers cert does not have non-repudiation bit set!");
            }
            throw new DigiDocException(DigiDocException.ERR_SIGNERS_CERT_NONREPUD,
                            "Signers cert does not have non-repudiation bit set!", null);
        }
        Signature sig = new Signature(sdoc);
        sig.setId(sId != null ? sId : sdoc.getNewSignatureId());
        if (profile != null) { // use new profile for this signature
            sig.setProfile(profile);
            if (sdoc.getProfile() == null || sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES))
                sdoc.setProfile(profile); // change also container to new profile
        } else
            // use default profile
            sig.setProfile(sdoc.getProfile());
        
        // create SignedInfo block
        SignedInfo si = new SignedInfo(sig, ((sSigMethod != null) ? sSigMethod : SignedDoc.RSA_SHA1_SIGNATURE_METHOD),
                        SignedDoc.CANONICALIZATION_METHOD_20010315);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signer: " + cert.getSubjectDN().getName() + " pre-2011: " + isPre2011IdCard(cert) + " digi-id: "
                            + isDigiIdCard(cert) + " 2011: " + is2011Card(cert));
        }
        if (sSigMethod == null) { // default values
            if (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                if (isPre2011IdCard(cert)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Generating rsa-sha224 signature for pre-2011 card");
                    }
                    si.setSignatureMethod(SignedDoc.RSA_SHA224_SIGNATURE_METHOD);
                } else {
                    String dType = "SHA-256";
                    String sSigMeth = DDUtils.digType2SigMeth(dType);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Generating digest: " + dType + " and signature: " + sSigMeth);
                    }
                    if (sSigMeth != null)
                        si.setSignatureMethod(sSigMeth);
                    else
                        throw new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM, "Invalid digest type: "
                                        + dType, null);
                }
            }
        }
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_XADES) || sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            si.setId(sig.getId() + "-SignedInfo");
        // add DataFile references
        for (int i = 0; i < sdoc.countDataFiles(); i++) {
            DataFile df = sdoc.getDataFile(i);
            if (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                if (!df.isDigestsCalculated()) {
                    try {
                        InputStream is = null;
                        if (df.getDfCacheFile() != null) is = df.getBodyAsStream();
                        if (is == null) is = sdoc.findDataFileAsStream(df.getFileName());
                        if (is == null) is = new java.io.FileInputStream(df.getFileName());
                        df.calcHashes(is);
                    } catch (java.io.FileNotFoundException ex) {
                        throw new DigiDocException(DigiDocException.ERR_READ_FILE, "Cannot read file: "
                                        + df.getFileName(), null);
                    }
                }
            } else {
                if (!df.isDigestsCalculated()) df.calculateFileSizeAndDigest(null);
            }
            if (LOG.isDebugEnabled()) LOG.debug("Add ref for df: " + df.getId());
            Reference ref = new Reference(si, df, sDigType);
            if (sdoc.getFormat().equals(SignedDoc.FORMAT_XADES) || sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                ref.setId(sig.getId() + "-ref-" + i);
            si.addReference(ref);
        }
        // create key info
        KeyInfo ki = new KeyInfo(cert);
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_XADES) || sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            ki.setId(sig.getId() + "-KeyInfo");
        sig.setKeyInfo(ki);
        ki.setSignature(sig);
        registerCert(cert, CertValue.CERTVAL_TYPE_SIGNER, null, sig);
        if (LOG.isDebugEnabled()) LOG.debug("Signer cert: " + cert.getSubjectDN().getName());
        
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_XADES) || sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            // first lookup in TSL-s
            X509Certificate ca = trustService.findCaForCert(cert);
            if (ca != null) {
                String caId = sig.getId() + "-" + DDUtils.getCommonName(ca.getSubjectDN().getName());
                registerCert(ca, CertValue.CERTVAL_TYPE_CA, caId, sig);
            }
            // TODO: maybe copy local CA certs to signature until the first ca that is in TSL?
        }
        // create signed properties
        SignedProperties sp = new SignedProperties(sig, cert, claimedRoles, adr);
        Reference ref = new Reference(si, sp, sDigType);
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_XADES) || sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            ref.setId(sig.getId() + "-ref-sp");
        si.addReference(ref);
        sig.setSignedInfo(si);
        sig.setSignedProperties(sp);
        sdoc.addSignature(sig);
        return sig;
    }
    
    /**
     * Finalizes XAdES BES signature form by setting binary signature value
     * 
     * @param sig Signature object
     * @param sigVal signature value
     * @return completed signature
     * @throws DigiDocException
     */
    public static Signature finalizeXadesBES(Signature sig, byte[] sigVal) throws DigiDocException {
        if (LOG.isDebugEnabled())
            LOG.debug("Finalize XAdES-BES sigval: " + ((sigVal != null) ? sigVal.length : 0) + " bytes");
        if (sigVal != null) sig.setSignatureValue(sigVal);
        return sig;
    }
    
    public Signature finalizeXadesT(SignedDoc sdoc, Signature sig) throws DigiDocException {
        if (LOG.isDebugEnabled()) LOG.debug("Finalize XAdES-T: " + sig.getId() + " profile: " + sig.getProfile());
        UnsignedProperties usp = new UnsignedProperties(sig);
        sig.setUnsignedProperties(usp);
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            DigiDocXmlGenerator genService = new DigiDocXmlGenerator(sdoc);
            // get <SignatureValueTimeStamp>
            StringBuffer sb = new StringBuffer();
            genService.signatureValue2xml(sb, sig.getSignatureValue(), true);
            String sSigValXml = sb.toString().trim();
            byte[] hash = DDUtils.digestOfType(sSigValXml.getBytes(),
                            (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                                            : DDUtils.SHA1_DIGEST_TYPE));
            if (LOG.isDebugEnabled())
                LOG.debug("Get sig-val-ts for: " + Base64Util.encode(hash) + " uri: " + tsaUrl + " DATA:\n---\n"
                                + sSigValXml + "\n---\n");
            TimeStampResponse tresp = timeStampService.requestTimestamp(TSPAlgorithms.SHA1, hash, tsaUrl);
            if (tresp != null) {
                TimestampInfo ti = new TimestampInfo(sig.getId() + "-T0", sig, TimestampInfo.TIMESTAMP_TYPE_SIGNATURE,
                                hash, tresp);
                ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-SIG"));
                sig.addTimestampInfo(ti);
                try {
                    if (LOG.isDebugEnabled()) LOG.debug("Timestamp: " + Base64Util.encode(tresp.getEncoded()));
                } catch (Exception ex) {
                }
                // TODO: add TSA refs and certs ? Not in TSL yet!
                sig.setProfile(SignedDoc.BDOC_PROFILE_T);
            }
        }
        return sig;
    }
    
    public Signature finalizeXadesC(SignedDoc sdoc, Signature sig) throws DigiDocException {
        if (LOG.isDebugEnabled()) LOG.debug("Finalize XAdES-C: " + sig.getId() + " profile: " + sig.getProfile());
        CompleteRevocationRefs rrefs = new CompleteRevocationRefs();
        CompleteCertificateRefs crefs = new CompleteCertificateRefs();
        UnsignedProperties usp = sig.getUnsignedProperties();
        if (usp == null) {
            usp = new UnsignedProperties(sig);
            sig.setUnsignedProperties(usp);
        }
        usp.setCompleteCertificateRefs(crefs);
        usp.setCompleteRevocationRefs(rrefs);
        rrefs.setUnsignedProperties(usp);
        crefs.setUnsignedProperties(usp);
        sig.setUnsignedProperties(usp);
        sig.setProfile(SignedDoc.BDOC_PROFILE_CL);
        // TODO: update certs and refs
        
        return sig;
    }
    
    public Signature finalizeXadesXL_TM(SignedDoc sdoc, Signature sig) throws DigiDocException {
        if (LOG.isDebugEnabled()) LOG.debug("Finalize XAdES-TM: " + sig.getId() + " profile: " + sig.getProfile());
        X509Certificate cert = sig.getKeyInfo().getSignersCertificate();
        String ocspUrl = trustService.findOcspUrlForCert(cert, 0);
        X509Certificate caCert = trustService.findCaForCert(cert);
        if (LOG.isDebugEnabled())
            LOG.debug("Get confirmation for cert: "
                            + ((cert != null) ? DDUtils.getCommonName(cert.getSubjectDN().getName()) : "NULL")
                            + " CA: "
                            + ((caCert != null) ? DDUtils.getCommonName(caCert.getSubjectDN().getName()) : "NULL")
                            + " URL: " + ((ocspUrl != null) ? ocspUrl : "NONE"));
        Notary not = notaryService.getConfirmation(sig, cert, caCert, null, ocspUrl);
        if (LOG.isDebugEnabled()) LOG.debug("Resp-id: " + not.getResponderId());
        String sRespId = DDUtils.getCommonName(not.getResponderId());
        X509Certificate rcert = notaryService.getNotaryCert(sRespId, not.getCertNr());
        if (LOG.isDebugEnabled())
            LOG.debug("Find responder cert by: " + sRespId + " and nr: " + not.getCertNr() + " found: "
                            + ((rcert != null) ? "OK" : "NO") + " format: " + sdoc.getFormat());
        // if the request was successful then create new data memebers
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) && (rcert != null)) {
            X509Certificate rcacert = trustService.findCaForCert(rcert);
            if (LOG.isDebugEnabled())
                LOG.debug("Register responders CA: " + ((rcacert != null) ? rcacert.getSubjectDN().getName() : "NULL"));
            String caId = not.getId() + "-" + DDUtils.getCommonName(rcacert.getSubjectDN().getName());
            registerCert(rcacert, CertID.CERTID_TYPE_RESPONDER_CA, caId, sig);
        }
        // add ocsp ref for this notary
        OcspRef orf = new OcspRef("#" + not.getId(), not.getResponderId(), not.getProducedAt(), (sdoc.getFormat()
                        .equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_ALGORITHM_1
                        : SignedDoc.SHA1_DIGEST_ALGORITHM), DDUtils.digestOfType(not.getOcspResponseData(), (sdoc
                        .getFormat().equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                        : DDUtils.SHA1_DIGEST_TYPE)));
        sig.getUnsignedProperties().getCompleteRevocationRefs().addOcspRef(orf);
        // mark status
        sig.setProfile(SignedDoc.BDOC_PROFILE_TM);
        // change profile
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) && sig.getPath() != null) {
            if (LOG.isDebugEnabled()) LOG.debug("Find signature: " + sig.getPath());
            ManifestFileEntry mfe = sdoc.findManifestEntryByPath(sig.getPath());
            if (mfe != null) {
                mfe.setMediaType(SignedDoc.MIME_SIGNATURE_BDOC_ + sdoc.getVersion() + "/" + sig.getProfile());
                if (LOG.isDebugEnabled())
                    LOG.debug("Change signature: " + sig.getPath() + " type: " + mfe.getMediaType());
            }
        }
        // TODO: update certs and refs
        return sig;
    }
    
    public Signature finalizeXadesXL_TS(SignedDoc sdoc, Signature sig) throws DigiDocException {
        if (LOG.isDebugEnabled()) LOG.debug("Finalize XAdES-TS: " + sig.getId() + " profile: " + sig.getProfile());
        if (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            DigiDocXmlGenerator genService = new DigiDocXmlGenerator(sdoc);
            // get <SignatureValueTimeStamp>
            StringBuffer sb = new StringBuffer();
            genService.signatureValue2xml(sb, sig.getSignatureValue(), true);
            //String sSigValXml = sb.toString().trim();
            genService.completeCertificateRefs2xml(sb, sig.getUnsignedProperties().getCompleteCertificateRefs(), sig,
                            true);
            genService.completeRevocationRefs2xml(sb, sig.getUnsignedProperties().getCompleteRevocationRefs(), sig,
                            true);
            String sSigAndRefsDat = sb.toString().trim();
            byte[] hash = DDUtils.digestOfType(sSigAndRefsDat.getBytes(),
                            (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                                            : DDUtils.SHA1_DIGEST_TYPE));
            if (LOG.isDebugEnabled())
                LOG.debug("Get sig-val-ts for: " + Base64Util.encode(hash) + " uri: " + tsaUrl + " DATA:\n---\n"
                                + sSigAndRefsDat + "\n---\n");
            TimeStampResponse tresp = timeStampService.requestTimestamp(TSPAlgorithms.SHA1, hash, tsaUrl);
            if (tresp != null) {
                TimestampInfo ti = new TimestampInfo(sig.getId() + "-T1", sig,
                                TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS, hash, tresp);
                ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-SIG"));
                ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-T0"));
                ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-CERTREFS"));
                ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-REVOCREFS"));
                sig.addTimestampInfo(ti);
                sig.setProfile(SignedDoc.BDOC_PROFILE_TS);
            }
        }
        return sig;
    }
    
    /**
     * Finalize signature to desired level
     * 
     * @param sdoc SignedDoc object
     * @param sig Signature object
     * @param sigVal signature value
     * @param profile profile. Use null for default (e.g. profile in signed doc)
     * @return finalized signature
     */
    public Signature finalizeSignature(SignedDoc sdoc, Signature sig, byte[] sigVal, String profile)
                    throws DigiDocException {
        String prf = profile;
        if (prf == null) prf = sdoc.getProfile();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Finalize sig: " + sig.getId() + " profile: " + prf + " sdoc: " + sdoc.getFormat() + "/"
                            + sdoc.getVersion());
        }
        // xades-bes
        finalizeXadesBES(sig, sigVal);
        if (prf != null) {
            // T
            if (prf.equals(SignedDoc.BDOC_PROFILE_T) || prf.equals(SignedDoc.BDOC_PROFILE_CL)
                            || prf.equals(SignedDoc.BDOC_PROFILE_TS)) finalizeXadesT(sdoc, sig);
            // C-L
            if (prf.equals(SignedDoc.BDOC_PROFILE_CL) || prf.equals(SignedDoc.BDOC_PROFILE_TM)
                            || prf.equals(SignedDoc.BDOC_PROFILE_TS)) finalizeXadesC(sdoc, sig);
            // TM
            if (prf.equals(SignedDoc.BDOC_PROFILE_TM) || prf.equals(SignedDoc.BDOC_PROFILE_TS))
                finalizeXadesXL_TM(sdoc, sig);
            // TS
            if (prf.equals(SignedDoc.BDOC_PROFILE_TS)) finalizeXadesXL_TS(sdoc, sig);
            
        }
        return sig;
    }
}
