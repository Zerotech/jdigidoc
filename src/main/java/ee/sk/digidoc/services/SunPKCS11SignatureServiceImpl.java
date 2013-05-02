package ee.sk.digidoc.services;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;

import sun.security.pkcs11.SunPKCS11;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.TokenKeyInfo;
import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;

public class SunPKCS11SignatureServiceImpl implements SignatureService {
    
    /** log4j logger */
    private static Logger LOG = Logger.getLogger(SunPKCS11SignatureServiceImpl.class);

    private Provider provider;

    private KeyStore keyStore;

    public String alias = null;
    
    private String driver = "opensc-pkcs11";
    
    public void setDriver(String driver) {
        this.driver = driver;
    }
    
    public SunPKCS11SignatureServiceImpl() {}
    
    public boolean load(String passwd, int slotNr) throws DigiDocException {
        provider = null;
        keyStore = null;
        boolean ok = initProvider(passwd, slotNr);
        if (ok) ok = initKeystore(passwd);
        return ok;
    }
    
    private boolean initProvider(String passwd, int slotNr) throws DigiDocException {
        try {
            String config = "name=OpenSC\n" + "library=" + driver + "\n" + "slotListIndex=" + slotNr;
            
            if (LOG.isDebugEnabled()) LOG.debug("init driver with config:\n---\n" + config + "\n---\n");
            
            byte[] bcfg = config.getBytes();
            ByteArrayInputStream confStream = new ByteArrayInputStream(bcfg);
            SunPKCS11 pkcs11 = new SunPKCS11(confStream);
            provider = (Provider) pkcs11;
            Security.addProvider(provider);
            
            if (LOG.isDebugEnabled()) LOG.debug("Driver inited");
            
            return true;
        } catch (Exception ex) {
            LOG.error("Error init provider: " + ex);
        }
        return false;
    }
    
    private boolean initKeystore(String passwd) throws DigiDocException {
        try {
            String javaLibPath = System.getProperty("java.library.path");

            if (LOG.isDebugEnabled())
                LOG.debug("init keystore" + " in: " + javaLibPath + " provider: "
                                + ((provider != null) ? "OK" : "NULL"));
            
            if (provider == null)
                throw new DigiDocException(DigiDocException.ERR_INIT_SIG_FAC, "Provider not initialized!", null);
            // load keystore
            keyStore = KeyStore.getInstance("PKCS11", provider);
            if (LOG.isDebugEnabled()) LOG.debug("Load keystore: " + provider.getName() + " - " + provider.getInfo());
            keyStore.load(null, passwd.toCharArray());
            // list keystore
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String al = aliases.nextElement();
                if (LOG.isDebugEnabled()) LOG.debug("Alias: " + al);
                if (alias == null) alias = al;
            }

            if (LOG.isDebugEnabled()) LOG.debug("Keystore loaded");

            return true;
        } catch (Exception ex) {
            if (ex instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
                if ("CKR_PIN_INCORRECT".equals(ex.getMessage())) {
                    DigiDocException.handleException(ex, DigiDocException.ERR_TOKEN_LOGIN);
                    //throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
                }
            }
            LOG.error("Error init keystore: " + ex);
        }
        return false;
    }
    
    /**
     * Reads all useable token keys
     * 
     * @return list of available token/key info
     * @throws DigiDocException
     */
    public List<TokenKeyInfo> getTokenKeys() throws DigiDocException {
        List<TokenKeyInfo> keys = new ArrayList<TokenKeyInfo>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String sAlias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(sAlias);
                TokenKeyInfo tok = new TokenKeyInfo(0, 0, null, sAlias.getBytes(), DDUtils.getCommonName(cert
                                .getSubjectDN().getName()), cert);
                keys.add(tok);
            }
        } catch (Exception ex) {
            LOG.error("Error init provider: " + ex);
        }
        return keys;
    }
    
    /**
     * Finds keys of specific type
     * 
     * @param bSign true if searching signature keys
     * @return array of key infos
     */
    public List<TokenKeyInfo> getTokensOfType(boolean bSign) {
        try {
            if (keyStore != null) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                TokenKeyInfo tki = new TokenKeyInfo(0, 0, null, alias.getBytes(), DDUtils.getCommonName(cert
                                .getSubjectDN().getName()), cert);
                List<TokenKeyInfo> list = new ArrayList<TokenKeyInfo>();
                list.add(tki);
                return list;
            }
        } catch (Exception ex) {
            LOG.error("Error init provider: " + ex);
        }
        return null;
    }
    
    /**
     * Method returns an array of strings representing the
     * list of available token names.
     * 
     * @return an array of available token names.
     * @throws DigiDocException if reading the token information fails.
     */
    public List<String> getAvailableTokenNames() throws DigiDocException {
        List<String> names = new ArrayList<String>();
        names.add(alias);
        return names;
    }
    
    /**
     * Method returns a digital signature. It finds the RSA private
     * key object from the active token and
     * then signs the given data with this key and RSA mechanism.
     * 
     * @param digest digest of the data to be signed.
     * @param token token index
     * @param pin users pin code
     * @param sig Signature object to provide info about desired signature method
     * @return an array of bytes containing digital signature.
     * @throws DigiDocException if signing the data fails.
     */
    public byte[] sign(byte[] digest, int token, String pin, Signature sig) throws DigiDocException {
        try {
            if (provider == null) initProvider(pin, token);
            if (keyStore == null) initKeystore(pin);
            if (keyStore == null) {
                LOG.error("Failed to load keystore");
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Keystore load failed", null);
            }
            
            try {
                if (LOG.isDebugEnabled())
                    LOG.debug("Signing: " + ConvertUtils.bin2hex(digest) + " len: " + digest.length + " with: " + alias
                                    + " on: " + provider.getName());
                byte[] ddata = DDUtils.addDigestAsn1Prefix(digest);
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keyStore.getKey(alias, pin.toCharArray()));
                byte[] sdata = cipher.doFinal(ddata);
                if (LOG.isDebugEnabled())
                    LOG.debug("Signature: " + ConvertUtils.bin2hex(sdata) + " len: " + sdata.length);
                return sdata;
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                // More likely bad password
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
            }
        } catch (Exception ex) {
            LOG.error("Error init provider: " + ex);
            ex.printStackTrace();
        }
        return null;
    }
    
    /**
     * Method returns a X.509 certificate object readed
     * from the active token and representing an
     * user public key certificate value.
     * 
     * @return X.509 certificate object.
     * @throws DigiDocException if getting X.509 public key certificate
     *             fails or the requested certificate type X.509 is not available in
     *             the default provider package
     */
    public X509Certificate getCertificate(int token, String pin) throws DigiDocException {
        try {
            if (provider == null) initProvider(pin, token);
            if (keyStore == null) initKeystore(pin);
            if (keyStore == null) {
                LOG.error("Failed to load keystore");
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Keystore load failed", null);
            }
            if (LOG.isDebugEnabled()) LOG.debug("Get cert for: " + alias + " on: " + provider.getName());
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            return cert;
        } catch (Exception ex) {
            LOG.error("Error init provider: " + ex);
            ex.printStackTrace();
        }
        return null;
    }
    
    /**
     * Method returns a X.509 certificate object readed
     * from the active token and representing an
     * user public key certificate value.
     * 
     * @return X.509 certificate object.
     * @throws DigiDocException if getting X.509 public key certificate
     *             fails or the requested certificate type X.509 is not available in
     *             the default provider package
     */
    public X509Certificate getAuthCertificate(int token, String pin) throws DigiDocException {
        return getCertificate(token, pin);
    }
    
    /**
     * Method closes the current session.
     * 
     * @throws DigiDocException if closing the session fails.
     */
    public void closeSession() throws DigiDocException {
        try {
            provider = null;
            keyStore = null;
            alias = null;
        } catch (Exception ex) {
            LOG.error("Error resetting pkcs11 factory: " + ex);
        }
    }
    
    /**
     * Resets the previous session
     * and other selected values
     */
    public void reset() throws DigiDocException {
        try {
            if (provider != null) {
                try {
                    Security.removeProvider(provider.getName());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
            provider = null;
            keyStore = null;
            alias = null;
        } catch (Exception ex) {
            LOG.error("Error resetting pkcs11 factory: " + ex);
        }
    }
    
    /**
     * Method decrypts the data with the RSA private key
     * corresponding to this certificate (which was used
     * to encrypt it). Decryption will be done on the card.
     * This operation closes the possibly opened previous
     * session with signature token and opens a new one with
     * authentication tokne if necessary
     * 
     * @param data data to be decrypted.
     * @param token index of authentication token
     * @param pin PIN code
     * @return decrypted data.
     * @throws DigiDocException for all decryption errors
     */
    public byte[] decrypt(byte[] data, int token, String pin) throws DigiDocException {
        try {
            if (provider == null) initProvider(pin, token);
            if (keyStore == null) initKeystore(pin);
            if (keyStore == null) {
                LOG.error("Failed to load keystore");
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Keystore load failed", null);
            }
            try {
                if (LOG.isDebugEnabled())
                    LOG.debug("Decrypting: " + ConvertUtils.bin2hex(data) + " len: " + data.length + " with: " + alias
                                    + " on: " + provider.getName());
                Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, keyStore.getKey(alias, pin.toCharArray()));
                byte[] ddata = cipher.doFinal(data);
                if (LOG.isDebugEnabled())
                    LOG.debug("Decrypted: " + ConvertUtils.bin2hex(ddata) + " len: " + ddata.length);
                return ddata;
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                // More likely bad password
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
            }
        } catch (Exception ex) {
            LOG.error("Error init provider: " + ex);
            ex.printStackTrace();
        }
        return null;
    }
    
    /**
     * Returns signature factory type identifier
     * 
     * @return factory type identifier
     */
    public String getType() {
        return SIGFAC_TYPE_PKCS11_SUN;
    }
}
