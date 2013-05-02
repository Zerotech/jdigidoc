package ee.sk.digidoc;

import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;

/**
 * Holds key info that represents a key on a cryptographic token (smartcard etc.)
 * 
 * @author Veiko Sinivee
 */
public class TokenKeyInfo implements Serializable {
    
    /** some order number */
    private int nr;
    /** token info */
    private transient Token token;
    /** slot id */
    private long slotId;
    /** key id */
    private byte[] keyId;
    /** certificate */
    private X509Certificate cert;
    
    private String label;
    
    private static Logger LOG = Logger.getLogger(TokenKeyInfo.class);
    
    /**
     * Constructor for TokenKeyInfo
     * 
     * @param nr order number
     * @param nSlot slot id
     * @param tok token info
     * @param id key id
     * @param label pkcs11 cert object label
     * @param cert certificate
     */
    public TokenKeyInfo(int nr, long slotId, Token token, byte[] keyId, String label, X509Certificate cert) {
        this.nr = nr;
        this.slotId = slotId;
        this.token = token;
        this.keyId = keyId;
        this.label = label;
        this.cert = cert;
    }
    
    public int getNr() {
        return nr;
    }
    
    public Token getToken() {
        return token;
    }
    
    public long getSlotId() {
        return slotId;
    }
    
    public byte[] getKeyId() {
        return keyId;
    }
    
    public X509Certificate getCert() {
        return cert;
    }
    
    public String getLabel() {
        return label;
    }
    
    public String getTokenName() {
        try {
            if (token != null) return token.getTokenInfo().getLabel();
        } catch (TokenException e) {
            LOG.error("Error reading token name: " + e);
        }
        return null;
    }
    
    public String getCertName() {
        if (cert != null) return DDUtils.getCommonName(cert.getSubjectDN().getName());
        return null;
    }
    
    public String getCertHex() {
        try {
            if (cert != null) return ConvertUtils.bin2hex(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            LOG.error("Error encoding cert: " + e);
        }
        return null;
    }
    
    public String getIdHex() {
        if (keyId != null) return ConvertUtils.bin2hex(keyId);
        return null;
    }
    
    public String getCertSerial() {
        if (cert != null) return cert.getSerialNumber().toString();
        return null;
    }
    
    public boolean isSignatureKey() {
        return checkCertKeyUsage(cert, 1);
    }
    
    public boolean isEncryptKey() {
        return checkCertKeyUsage(cert, 2);
    }
    
    /**
     * Checks if cert has certain key-usage bit set
     * 
     * @param cert certificate
     * @param nKu key-usage flag nr
     * @return true if set
     */
    private static boolean checkCertKeyUsage(X509Certificate cert, int flagNr) {
        if (cert != null) {
            boolean keyUsages[] = cert.getKeyUsage();
            if (keyUsages != null && flagNr >= 0 && keyUsages.length > flagNr && keyUsages[flagNr] == true) {
                return true;
            }
        }
        return false;
    }
}
