package ee.sk.utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

public class DDUtils {

    /**
     * Computes an SHA1 digest
     * 
     * @param data
     *            input data
     * @return SHA1 digest
     */
    public static byte[] digest(byte[] data) throws DigiDocException {
        byte[] dig = null;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(data);
            dig = sha.digest();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        return dig;
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
                while (idx1 < dn.length() && !Character.isLetter(dn.charAt(idx1)))
                    idx1++;
                int idx2 = idx1;
                while (idx2 < dn.length() && dn.charAt(idx2) != ',' && dn.charAt(idx2) != '/')
                    idx2++;
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

}
