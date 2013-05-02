package ee.sk.utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.SignedInfo;
import ee.sk.digidoc.SignedProperties;
import ee.sk.digidoc.services.CanonicalizationService;
import ee.sk.digidoc.services.DigiDocXmlGenerator;

public class DDUtils {
    
    public static final String SHA1_DIGEST_TYPE = "SHA-1";
    public static final String SHA224_DIGEST_TYPE = "SHA-224";
    public static final String SHA256_DIGEST_TYPE = "SHA-256";
    public static final String SHA512_DIGEST_TYPE = "SHA-512";
    
    /** SHA1 prefix - 00 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 */
    private static final byte[] sha1AlgPrefix = { 0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                    0x04, 0x14 };
    private static final byte[] sha1AlgPrefix2 = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                    0x05, 0x00, 0x04, 0x14 };
    
    /** SHA224 prefix - 00302d300d06096086480165030402040500041c */
    private static final byte[] sha224AlgPrefix = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
                    0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c };
    /**
     * sha256 prefix -
     * 003031300d0609608648016503040201050004205ad8f86f90558d973aba4ce9be116646efd2c57758e5238b841d50abe788bae9
     */
    private static final byte[] sha256AlgPrefix = { 48, 49, 48, 13, 6, 9, 96, (byte) 134, 72, 1, 101, 3, 4, 2, 1, 5, 0,
                    4, 32 };

    private static final byte[] sha512AlgPrefix = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
                    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

    /**
     * Computes an SHA1 digest
     * 
     * @param data
     *            input data
     * @return SHA1 digest
     */
    public static byte[] digest(byte[] data) {
        return digestOfType(data, SHA1_DIGEST_TYPE);
    }
    
    /**
     * Computes a digest
     * 
     * @param data input data
     * @param digType digest type
     * @return digest value
     */
    public static byte[] digestOfType(byte[] data, String digType) {
        byte[] dig = null;
        try {
            MessageDigest sha = MessageDigest.getInstance(digType, "BC");
            sha.update(data);
            dig = sha.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return dig;
    }
    
    /**
     * Calculates the digest of SignedInfo block If the user has set origDigest
     * attribute which is allways done when reading the XML file, then this
     * digest is returned otherwise a new digest is calculated.
     * 
     * @return SignedInfo block digest
     */
    public static byte[] calculateDigest(SignedInfo signedInfo, CanonicalizationService canonicalizationService)
                    throws DigiDocException {
        if (signedInfo.getOrigDigest() == null) {
            DigiDocXmlGenerator xmlGenerator = new DigiDocXmlGenerator(signedInfo.getSignature().getSignedDoc());
            byte[] xml = xmlGenerator.signedInfoToXML(signedInfo.getSignature(), signedInfo);
            byte[] tmp = canonicalizationService.canonicalize(xml, SignedDoc.CANONICALIZATION_METHOD_20010315);
            byte[] hash = null;
            if (signedInfo.getSignatureMethod().equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD))
                hash = DDUtils.digestOfType(tmp, DDUtils.SHA1_DIGEST_TYPE);
            if (signedInfo.getSignatureMethod().equals(SignedDoc.RSA_SHA256_SIGNATURE_METHOD))
                hash = DDUtils.digestOfType(tmp, DDUtils.SHA256_DIGEST_TYPE);
            if (signedInfo.getSignatureMethod().equals(SignedDoc.RSA_SHA224_SIGNATURE_METHOD))
                hash = DDUtils.digestOfType(tmp, DDUtils.SHA224_DIGEST_TYPE);
            if (signedInfo.getSignatureMethod().equals(SignedDoc.RSA_SHA512_SIGNATURE_METHOD))
                hash = DDUtils.digestOfType(tmp, DDUtils.SHA512_DIGEST_TYPE);
            return hash;
        } else {
            return signedInfo.getOrigDigest();
        }
    }
    
    /**
     * Calculates the digest of SignedProperties block
     * 
     * @return SignedProperties block digest
     */
    public static byte[] calculateDigest(SignedProperties signedProperties,
                    CanonicalizationService canonicalizationService)
                    throws DigiDocException {
        if (signedProperties.getOrigDigest() == null) {
            DigiDocXmlGenerator xmlService = new DigiDocXmlGenerator(signedProperties.getSignature().getSignedDoc());
            byte[] xml = xmlService.signedPropertiesToXML(signedProperties.getSignature(), signedProperties);
            byte[] tmp = canonicalizationService.canonicalize(xml, SignedDoc.CANONICALIZATION_METHOD_20010315);
            String sDigType = DDUtils.getDefaultDigestType(signedProperties.getSignature().getSignedDoc());
            byte[] hash = DDUtils.digestOfType(tmp, sDigType);
            return hash;
        } else {
            return signedProperties.getOrigDigest();
        }
    }

    /**
     * return CN part of DN
     * 
     * @return CN part of DN or null
     */
    public static String getCommonName(String dn) {
        String name = null;
        if (dn != null) {
            int idx1 = dn.indexOf("CN=");
            if (idx1 != -1) {
                idx1 += 2;
                while (idx1 < dn.length() && !Character.isLetter(dn.charAt(idx1))) {
                    idx1++;
                }
                int idx2 = idx1;
                while (idx2 < dn.length() && dn.charAt(idx2) != '\"' && dn.charAt(idx2) != '\\'
                                && dn.charAt(idx2) != ',' && dn.charAt(idx2) != '/') {
                    idx2++;
                }
                name = dn.substring(idx1, idx2);
            }
        }
        return name;
    }

    /**
     * Reads X509 certificate from a data stream
     * 
     * @param data
     *            input data in Base64 form
     * @return X509Certificate object
     * @throws EFormException
     *             for all errors
     */
    public static X509Certificate readCertificate(byte[] data) throws DigiDocException {
        X509Certificate cert = null;
        try {
            // ByteArrayInputStream certStream = new
            // ByteArrayInputStream(Base64Util.decode(data));
            ByteArrayInputStream certStream = new ByteArrayInputStream(data);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(certStream);
            certStream.close();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_CERT);
        }
        return cert;
    }

    /**
     * Reads the cert from a file, URL or from another location somewhere in the
     * CLASSPATH such as in the librarys jar file.
     * 
     * @param certLocation
     *            certificates file name, or URL. You can use url in form
     *            jar://<location> to read a certificate from the car file or
     *            some other location in the CLASSPATH
     * @return certificate object
     */
    public static X509Certificate readCertificate(String certLocation) throws DigiDocException {
        X509Certificate cert = null;
        try {
            InputStream isCert = null;
            URL url = null;
            if (certLocation.startsWith("http")) {
                url = new URL(certLocation);
                isCert = url.openStream();
            } else if (certLocation.startsWith("jar://")) {
                isCert = SignedDoc.class.getResourceAsStream(certLocation.substring(6));
            } else {
                isCert = new FileInputStream(certLocation);
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certificateFactory.generateCertificate(isCert);
            isCert.close();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        return cert;
    }

    /**
     * Helper method for comparing digest values
     * 
     * @param dig1
     *            first digest value
     * @param dig2
     *            second digest value
     * @return true if they are equal
     */
    public static boolean compareDigests(byte[] dig1, byte[] dig2) {
        boolean ok = (dig1 != null) && (dig2 != null) && (dig1.length == dig2.length);
        
        for (int i = 0; ok && (i < dig1.length); i++) {
            if (dig1[i] != dig2[i]) {
                ok = false;
            }
        }
        
        return ok;
    }
    
    public static String convX509Name(X500Principal principal) {
        String sName = principal.getName("RFC2253");
        return sName;
    }
    
    /**
     * Returns default digest type value
     * 
     * @param sdoc SignedDoc object
     * @return default digest type
     */
    public static String getDefaultDigestType(SignedDoc sdoc) {
        if (sdoc != null && sdoc.getFormat() != null && sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            return SHA256_DIGEST_TYPE;
        else
            return SHA1_DIGEST_TYPE;
    }
    
    /**
     * Returns digest algorithm URI corresponding to
     * searched digest type value
     * 
     * @param digType digest type
     * @return digest algorithm URI
     */
    public static String digType2Alg(String digType) {
        if (digType != null) {
            if (digType.equals(SHA1_DIGEST_TYPE)) return SignedDoc.SHA1_DIGEST_ALGORITHM;
            if (digType.equals(SHA224_DIGEST_TYPE)) return SignedDoc.SHA224_DIGEST_ALGORITHM;
            if (digType.equals(SHA256_DIGEST_TYPE)) return SignedDoc.SHA256_DIGEST_ALGORITHM_1;
            if (digType.equals(SHA512_DIGEST_TYPE)) return SignedDoc.SHA512_DIGEST_ALGORITHM;
        }
        return null;
    }
    
    /**
     * Returns digest type for given algorithm URI
     * 
     * @param digAlg digest algorithm URI
     * @return digest type
     */
    public static String digAlg2Type(String digAlg) {
        if (digAlg != null) {
            if (digAlg.equals(SignedDoc.SHA1_DIGEST_ALGORITHM)) return SHA1_DIGEST_TYPE;
            if (digAlg.equals(SignedDoc.SHA224_DIGEST_ALGORITHM)) return SHA224_DIGEST_TYPE;
            if (digAlg.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_1)
                            || digAlg.equals(SignedDoc.SHA256_DIGEST_ALGORITHM_2)) return SHA256_DIGEST_TYPE;
            if (digAlg.equals(SignedDoc.SHA512_DIGEST_ALGORITHM)) return SHA512_DIGEST_TYPE;
        }
        return null;
    }
    
    /**
     * Returns digest type for given signature method URI
     * 
     * @param sigMeth signature method algorithm URI
     * @return digest type
     */
    public static String sigMeth2Type(String sigMeth) {
        if (sigMeth != null) {
            if (sigMeth.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD)) return SHA1_DIGEST_TYPE;
            if (sigMeth.equals(SignedDoc.RSA_SHA224_SIGNATURE_METHOD)) return SHA224_DIGEST_TYPE;
            if (sigMeth.equals(SignedDoc.RSA_SHA256_SIGNATURE_METHOD)) return SHA256_DIGEST_TYPE;
            if (sigMeth.equals(SignedDoc.RSA_SHA512_SIGNATURE_METHOD)) return SHA512_DIGEST_TYPE;
        }
        return null;
    }
    
    /**
     * Returns signature method URI corresponding to
     * searched digest type value
     * 
     * @param digType digest type
     * @return signature method URI
     */
    public static String digType2SigMeth(String digType) {
        if (digType != null) {
            if (digType.equals(SHA1_DIGEST_TYPE)) return SignedDoc.RSA_SHA1_SIGNATURE_METHOD;
            if (digType.equals(SHA224_DIGEST_TYPE)) return SignedDoc.RSA_SHA224_SIGNATURE_METHOD;
            if (digType.equals(SHA256_DIGEST_TYPE)) return SignedDoc.RSA_SHA256_SIGNATURE_METHOD;
            if (digType.equals(SHA512_DIGEST_TYPE)) return SignedDoc.RSA_SHA512_SIGNATURE_METHOD;
        }
        return null;
    }
    
    /**
     * Adds ASN.1 structure prefix to digest value to be signed
     * 
     * @param digest digest value to be signed
     * @return prefixed digest value
     */
    public static byte[] addDigestAsn1Prefix(byte[] digest) {
        byte[] ddata = null;
        if (digest.length == SignedDoc.SHA1_DIGEST_LENGTH) {
            ddata = new byte[sha1AlgPrefix.length + digest.length];
            System.arraycopy(sha1AlgPrefix, 0, ddata, 0, sha1AlgPrefix.length);
            System.arraycopy(digest, 0, ddata, sha1AlgPrefix.length, digest.length);
        }
        if (digest.length == SignedDoc.SHA224_DIGEST_LENGTH) {
            ddata = new byte[sha224AlgPrefix.length + digest.length];
            System.arraycopy(sha224AlgPrefix, 0, ddata, 0, sha224AlgPrefix.length);
            System.arraycopy(digest, 0, ddata, sha224AlgPrefix.length, digest.length);
        }
        if (digest.length == SignedDoc.SHA256_DIGEST_LENGTH) {
            ddata = new byte[sha256AlgPrefix.length + digest.length];
            System.arraycopy(sha256AlgPrefix, 0, ddata, 0, sha256AlgPrefix.length);
            System.arraycopy(digest, 0, ddata, sha256AlgPrefix.length, digest.length);
        }
        if (digest.length == SignedDoc.SHA512_DIGEST_LENGTH) {
            ddata = new byte[sha512AlgPrefix.length + digest.length];
            System.arraycopy(sha512AlgPrefix, 0, ddata, 0, sha512AlgPrefix.length);
            System.arraycopy(digest, 0, ddata, sha512AlgPrefix.length, digest.length);
        }
        return ddata;
    }
    
    /**
     * Checks if this certificate has non-repudiation bit set
     * 
     * @param cert X509Certificate object
     * @return true if ok
     */
    public static boolean isSignatureKey(X509Certificate cert) {
        if (cert != null) {
            boolean keyUsages[] = cert.getKeyUsage();
            if (keyUsages != null && keyUsages.length > 2 && keyUsages[1] == true) return true;
        }
        return false;
    }
    
    public static boolean compareBytes(byte[] srch, byte[] from, int idx1) {
        if (srch != null && from != null && idx1 >= 0 && ((idx1 + srch.length) < from.length)) {
            for (int i = idx1; i < idx1 + srch.length; i++) {
                if (from[i] != srch[i - idx1]) return false;
            }
            return true;
        }
        return false;
    }
    
    public static String findDigType(byte[] digest) {
        if (compareBytes(sha1AlgPrefix, digest, 0) || compareBytes(sha1AlgPrefix2, digest, 0)) return SHA1_DIGEST_TYPE;
        if (compareBytes(sha224AlgPrefix, digest, 0)) return SHA224_DIGEST_TYPE;
        if (compareBytes(sha256AlgPrefix, digest, 0)) return SHA256_DIGEST_TYPE;
        if (compareBytes(sha512AlgPrefix, digest, 0)) return SHA512_DIGEST_TYPE;
        return null;
    }
    
    public static byte[] removePrefix(byte[] digest) {
        int nLen = 0;
        if (compareBytes(sha1AlgPrefix, digest, 0))
            nLen = sha1AlgPrefix.length;
        else if (compareBytes(sha1AlgPrefix2, digest, 0))
            nLen = sha1AlgPrefix2.length;
        else if (compareBytes(sha224AlgPrefix, digest, 0))
            nLen = sha224AlgPrefix.length;
        else if (compareBytes(sha256AlgPrefix, digest, 0))
            nLen = sha256AlgPrefix.length;
        else if (compareBytes(sha512AlgPrefix, digest, 0)) nLen = sha512AlgPrefix.length;
        if (nLen > 0) {
            byte[] ndig = new byte[digest.length - nLen];
            System.arraycopy(digest, digest.length - ndig.length, ndig, 0, ndig.length);
            return ndig;
        }
        return null;
    }
}
