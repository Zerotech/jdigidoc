package ee.sk.digidoc.services;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.TokenKeyInfo;

public class PKCS12SignatureServiceImpl implements SignatureService {
    
    private KeyStore keyStore;
    /** log4j logger */
    private static Logger LOG = Logger.getLogger(PKCS12SignatureServiceImpl.class);
    /** security provider */
    private Provider securityProvider;
    
    public PKCS12SignatureServiceImpl() throws DigiDocException {
        initProvider();
    }
    
    public boolean load(String storeName, String storeType, String passwd) throws DigiDocException {
        try {
            if (LOG.isDebugEnabled()) LOG.debug("Load store: " + storeName + " type: " + storeType);
            keyStore = KeyStore.getInstance(storeType);
            if (keyStore != null) {
                keyStore.load(new FileInputStream(storeName), passwd.toCharArray());
                return true;
            }
        } catch (Exception ex) {
            LOG.error("Error loading store: " + storeName + " - " + ex);
        }
        return false;
    }
    
    /**
     * Initializes Java cryptography provider
     */
    private void initProvider() throws DigiDocException {
        try {
            securityProvider = (Provider) Class.forName(DIGIDOC_SECURITY_PROVIDER).newInstance();
            Security.addProvider(securityProvider);
        } catch (Exception ex) {
            securityProvider = null;
            DigiDocException.handleException(ex, DigiDocException.ERR_CRYPTO_PROVIDER);
        }
    }

    /**
     * Reads all useable token keys
     * 
     * @return list of available token/key info
     * @throws DigiDocException
     */
    public List<TokenKeyInfo> getTokenKeys() throws DigiDocException {
        return null;
    }
    
    /**
     * Finds keys of specific type
     * 
     * @param bSign true if searching signature keys
     * @return array of key infos
     */
    public List<TokenKeyInfo> getTokensOfType(boolean signatureKeys) {
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
        try {
            if (keyStore != null) {
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    names.add(alias);
                }
            }
        } catch (Exception ex) {
            LOG.error("Error reading store aliases: " + ex);
        }
        return names;
    }
    
    /**
     * Returns the n-th token name or alias
     * 
     * @param nIdx index of token
     * @return alias
     */
    private String getTokenName(int index) {
        try {
            if (keyStore != null) {
                Enumeration<String> aliases = keyStore.aliases();
                for (int i = 0; aliases.hasMoreElements(); i++) {
                    String alias = aliases.nextElement();
                    if (i == index) return alias;
                }
            }
        } catch (Exception ex) {
            LOG.error("Error reading store aliases: " + ex);
        }
        return null;
    }

    /**
     * Method returns a digital signature. It finds the RSA private
     * key object from the active token and
     * then signs the given data with this key and RSA mechanism.
     * 
     * @param digest digest of the data to be signed.
     * @param token token index
     * @param passwd users pin code or in case of pkcs12 file password
     * @param sig Signature object to provide info about desired signature method
     * @return an array of bytes containing digital signature.
     * @throws DigiDocException if signing the data fails.
     */
    public byte[] sign(byte[] digest, int token, String pin, Signature sig) throws DigiDocException {
        try {
            if (keyStore == null)
                throw new DigiDocException(DigiDocException.ERR_NOT_INITED, "Keystore not initialized", null);

            String alias = getTokenName(token);
            if (alias == null)
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid token nr: " + token, null);
            // get key
            if (LOG.isDebugEnabled())
                LOG.debug("loading key: " + alias + " passwd-len: " + ((pin != null) ? pin.length() : 0));

            Key key = keyStore.getKey(alias, pin.toCharArray());

            if (LOG.isDebugEnabled())
                LOG.debug("Key: " + ((key != null) ? "OK, algorithm: " + key.getAlgorithm() : "NULL"));

            if (key == null)
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid password for token nr: " + token,
                                null);

            String sigMeth = null;

            if (sig != null && sig.getSignedInfo() != null && sig.getSignedInfo().getSignatureMethod() != null)
                sigMeth = sig.getSignedInfo().getSignatureMethod();

            if (LOG.isDebugEnabled()) LOG.debug("Signing\n---\n" + new String(digest) + "\n---\n");

            java.security.Signature instance = null;
            if (sigMeth != null) {
                if (sig.getSignedInfo().getSignatureMethod().equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD))
                    instance = java.security.Signature.getInstance("SHA1withRSA");
                else if (sig.getSignedInfo().getSignatureMethod().equals(SignedDoc.RSA_SHA224_SIGNATURE_METHOD))
                    instance = java.security.Signature.getInstance("SHA224withRSA");
                else if (sig.getSignedInfo().getSignatureMethod().equals(SignedDoc.RSA_SHA256_SIGNATURE_METHOD))
                    instance = java.security.Signature.getInstance("SHA256withRSA");
                else if (sig.getSignedInfo().getSignatureMethod().equals(SignedDoc.RSA_SHA512_SIGNATURE_METHOD))
                    instance = java.security.Signature.getInstance("SHA512withRSA");
            }
            if (instance == null)
                throw new DigiDocException(DigiDocException.ERR_SIGNATURE_METHOD, "SignatureMethod not specified!",
                                null);

            instance.initSign((PrivateKey) key);
            instance.update(digest);
            byte[] signature = instance.sign();

            if (LOG.isDebugEnabled()) LOG.debug("Signature len: " + ((signature != null) ? signature.length : 0));

            return signature;
        } catch (Exception ex) {
            LOG.error("Error signing: " + ex);
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
        if (keyStore == null)
            throw new DigiDocException(DigiDocException.ERR_NOT_INITED, "Keystore not initialized", null);
        String alias = getTokenName(token);
        if (alias == null)
            throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid token nr: " + token, null);
        try {
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (Exception ex) {
            LOG.error("Error reading cert for alias: " + alias + " - " + ex);
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
     * Resets the previous session
     * and other selected values
     */
    public void reset() throws DigiDocException {
        keyStore = null;
    }
    
    /**
     * Method closes the current session.
     * 
     * @throws DigiDocException if closing the session fails.
     */
    public void closeSession() throws DigiDocException {
        reset();
    }
    
    /**
     * Method decrypts the data with the RSA private key
     * corresponding to this certificate (which was used
     * to encrypt it). Decryption will be done with keystore
     * 
     * @param data data to be decrypted.
     * @param token index of authentication token
     * @param pin PIN code
     * @return decrypted data.
     * @throws DigiDocException for all decryption errors
     */
    public byte[] decrypt(byte[] data, int token, String pin) throws DigiDocException {
        try {
            if (keyStore == null)
                throw new DigiDocException(DigiDocException.ERR_NOT_INITED, "Keystore not initialized", null);

            String alias = getTokenName(token);
            if (alias == null)
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid token nr: " + token, null);
            // get key
            if (LOG.isDebugEnabled())
                LOG.debug("loading key: " + alias + " passwd-len: " + ((pin != null) ? pin.length() : 0));

            Key key = keyStore.getKey(alias, pin.toCharArray());

            if (LOG.isDebugEnabled())
                LOG.debug("Key: " + ((key != null) ? "OK, algorithm: " + key.getAlgorithm() : "NULL"));

            if (key == null)
                throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid password for token: " + alias,
                                null);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decdata = cipher.doFinal(data);

            if (LOG.isDebugEnabled()) LOG.debug("Decrypted len: " + ((decdata != null) ? decdata.length : 0));

            return decdata;
        } catch (Exception ex) {
            LOG.error("Error decrypting: " + ex);
        }
        return null;
    }
    
    /**
     * Returns signature factory type identifier
     * 
     * @return factory type identifier
     */
    public String getType() {
        return SIGFAC_TYPE_PKCS12;
    }
}
