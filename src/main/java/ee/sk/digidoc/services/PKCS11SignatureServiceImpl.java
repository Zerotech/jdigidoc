package ee.sk.digidoc.services;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.ByteArrayInputStream;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.TokenKeyInfo;
import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;

/**
 * PKCS#11 based signature implementation
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class PKCS11SignatureServiceImpl implements SignatureService {
    
    /** Object represent a current PKCS#11 module. */
    private Module pkcs11Module;
    /** An array of available tokens. */
    private List<TokenKeyInfo> tokens;
    /** A current session object are used to perform cryptographic operations on a token. */
    private Session currentSession;
    /** selected (current token) */
    private TokenKeyInfo selectedToken;
    /** security provider */
    private Provider securityProvider;
    /** log4j logger */
    private static Logger LOG = Logger.getLogger(PKCS11SignatureServiceImpl.class);
    /** PKCS#11 module is initialized */
    private static boolean isInitialized = false;
    
    private final String DIGIDOC_SIGN_PKCS11_DRIVER = "opensc-pkcs11";
    
    private boolean keyUsageCheck = true;
    
    public void setKeyUsageCheck(boolean keyUsageCheck) {
        this.keyUsageCheck = keyUsageCheck;
    }

    public PKCS11SignatureServiceImpl() throws DigiDocException {
        if (pkcs11Module == null) initPKCS11();
        if (securityProvider == null) initProvider();
    }
    
    /**
     * initializes the PKCS#11 subsystem
     */
    private void initPKCS11() throws DigiDocException {
        try {
            if (LOG.isInfoEnabled())
                LOG.info("Loading PKCS11 driver: " + DIGIDOC_SIGN_PKCS11_DRIVER + " libpath: "
                                + System.getProperty("java.library.path"));
            // load PKCS11 module
            pkcs11Module = AccessController.doPrivileged(new PrivilegedExceptionAction<Module>() {
                public Module run() throws Exception {
                    Module m = Module.getInstance(DIGIDOC_SIGN_PKCS11_DRIVER);
                    return m;
                }
            });
            
            try {
                if (!isInitialized) {
                    pkcs11Module.initialize(null); // initializes the module
                    isInitialized = true;
                }
            } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception ex) {
                LOG.error("Pkcs11 error: " + ex);
                if (ex.getErrorCode() == PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                    LOG.error("PKCS11 already loaded ok");
                    isInitialized = true;
                } else
                    DigiDocException.handleException(ex, DigiDocException.ERR_CRYPTO_DRIVER);
            }
            
            tokens = getTokenKeys();
        } catch (Exception e) {
            pkcs11Module = null; // reset since we had an error
            DigiDocException.handleException(e, DigiDocException.ERR_CRYPTO_DRIVER);
        }
        
        if ((tokens == null) || (tokens.isEmpty()))
            throw new DigiDocException(DigiDocException.ERR_PKCS11_INIT,
                            "Error reading signature certificates from card!", null);
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
        List<TokenKeyInfo> tokenKeys = new ArrayList<TokenKeyInfo>();
        Session sess = null;
        
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);
            int nr = 0;
            for (int i = 0; (slots != null) && (i < slots.length); i++) {
                SlotInfo si = slots[i].getSlotInfo(); // get information about this slot object
                if (LOG.isDebugEnabled()) LOG.debug("Slot " + i + ": " + si);
                if (si.isTokenPresent()) { // indicates, if there is a token present in this slot
                    Token tok = slots[i].getToken();
                    if (LOG.isDebugEnabled()) LOG.debug("Token: " + tok);
                    sess = tok.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION,
                                    null, null);
                    X509PublicKeyCertificate templCert = new X509PublicKeyCertificate();
                    sess.findObjectsInit(templCert);
                    iaik.pkcs.pkcs11.objects.Object[] certs = null;
                    do {
                        certs = sess.findObjects(1); // find next cert
                        if (certs != null && certs.length > 0) {
                            if (LOG.isDebugEnabled()) LOG.debug("Certs: " + certs.length);
                            for (int j = 0; j < certs.length; j++) {
                                X509PublicKeyCertificate x509 = (X509PublicKeyCertificate) certs[j];
                                byte[] derCert = x509.getValue().getByteArrayValue();
                                X509Certificate cert = (X509Certificate) certFactory
                                                .generateCertificate(new ByteArrayInputStream(derCert));
                                TokenKeyInfo tki = new TokenKeyInfo(nr, slots[i].getSlotID(), tok, x509.getId()
                                                .getByteArrayValue(), x509.getLabel().toString(), cert);
                                nr++;
                                if (LOG.isDebugEnabled())
                                    LOG.debug("Slot: " + i + " cert: " + j + " nr: " + tki.getCertSerial() + " CN: "
                                                    + tki.getCertName() + " id: " + tki.getIdHex() + " signature: "
                                                    + tki.isSignatureKey());
                                tokenKeys.add(tki);
                            }
                        } // loop until all certs read
                    } while (certs != null && certs.length > 0);
                    sess.closeSession();
                    sess = null;
                }
            }
        } catch (Exception e) {
            pkcs11Module = null; // reset since we had an error
            DigiDocException.handleException(e, DigiDocException.ERR_CRYPTO_DRIVER);
        } finally {
            try {
                if (sess != null) sess.closeSession();
            } catch (Exception ex) {
                LOG.error("Error closing session: " + ex);
            }
        }

        return tokenKeys;
    }
    
    /**
     * Finds keys of specific type
     * 
     * @param bSign true if searching signature keys
     * @return array of key infos
     */
    public List<TokenKeyInfo> getTokensOfType(boolean signatureKeys) {
        List<TokenKeyInfo> tokensOfType = new ArrayList<TokenKeyInfo>();
        
        for (TokenKeyInfo tki : tokens) {
            if ((signatureKeys && (tki.isSignatureKey() || !keyUsageCheck)) || (!signatureKeys && tki.isEncryptKey())) {
                if (LOG.isDebugEnabled())
                    LOG.debug("Using token: is-sign: " + tki.isSignatureKey() + " is-crypt: " + tki.isEncryptKey()
                                    + " nr: " + tki.getCertSerial() + " CN: " + tki.getCertName() + " id: "
                                    + tki.getIdHex());
                tokensOfType.add(tki);
            }
        }
        
        return tokensOfType;
    }
    
    /**
     * Finds token with slot id and certificate label
     * 
     * @param nSlotId slot id
     * @param label cert label
     * @return found token or null
     */
    public TokenKeyInfo getTokenWithSlotIdAndLabel(long slotId, String label) {
        for (TokenKeyInfo tki : tokens) {
            if (tki.getSlotId() == slotId && tki.getLabel().equals(label)) return tki;
        }
        return null;
    }
    
    /**
     * Returns a list of all available key names (cert CN)
     * 
     * @return an array of all available key names (cert CN)
     * @throws DigiDocException if reading the token information fails.
     */
    public List<String> getAvailableTokenNames() throws DigiDocException {
        if (pkcs11Module == null) initPKCS11();

        List<String> names = new ArrayList<String>();

        for (TokenKeyInfo tki : tokens) {
            names.add(tki.getCertName()); // get the label of this token
        }

        return names;
    }
    
    private void startSession(TokenKeyInfo tki, String pin) throws DigiDocException {
        try {
            if (tki != null) {
                // open a new session to perfom operations on this token
                currentSession = tki.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                                Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                selectedToken = tki;
            } else if (LOG.isDebugEnabled()) LOG.debug("No suitable token found!");
            // logs in the user or the security officer to the session
            if (currentSession != null && selectedToken != null) {
                if (LOG.isDebugEnabled())
                    LOG.debug("Login for: " + selectedToken.getCertName() + " id: " + selectedToken.getIdHex());
                try {
                    currentSession.login(Session.UserType.USER, pin.toCharArray());
                } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception ex) {
                    LOG.error("Pkcs11 error: " + ex);
                    if (ex.getErrorCode() == PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN) {
                        LOG.error("User already logged in ok");
                    } else
                        DigiDocException.handleException(ex, DigiDocException.ERR_TOKEN_LOGIN);
                }
            }
        } catch (TokenException e) {
            selectedToken = null;
            currentSession = null;
            DigiDocException.handleException(e, DigiDocException.ERR_TOKEN_LOGIN);
        }
    }

    /**
     * Method opens a new session to perfom operations on
     * specified token and logs in the user
     * or the security officer to the session.
     * 
     * @param bSignSession true if we want to open a session with signature token
     * @param token tokens order number
     * @param pin the PIN.
     * @throws DigiDocException if the session could not be opened or if login fails.
     */
    public void openSession(TokenKeyInfo tki, String pin) throws DigiDocException {
        if (pkcs11Module == null) initPKCS11();
        
        if (currentSession != null) closeSession();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Open session for token: " + tki);
            LOG.debug("Open session for: "
                            + ((tki != null) ? tki.getCertName() + " id: " + tki.getIdHex() + " sign: "
                                            + tki.isSignatureKey() + " crypt: " + tki.isEncryptKey() : "NULL"));
        }
        
        startSession(tki, pin);
    }
    
    /**
     * Method opens a new session to perfom operations on
     * specified token and logs in the user
     * or the security officer to the session.
     * 
     * @param bSignSession true if we want to open a session with signature token
     * @param token tokens order number
     * @param pin the PIN.
     * @throws DigiDocException if the session could not be opened or if login fails.
     */
    public void openSession(boolean signSession, int token, String pin) throws DigiDocException {
        if (pkcs11Module == null) initPKCS11();
        
        // don't login if the session exists
        if (currentSession == null || selectedToken == null || (signSession && !selectedToken.isSignatureKey())
                        || (!signSession && selectedToken.isSignatureKey())) {
            // close the old session if necessary
            if (currentSession != null) closeSession();
            if (LOG.isDebugEnabled()) LOG.debug("Open session for token: " + token);
            TokenKeyInfo tki = null;
            
            List<TokenKeyInfo> tkis = getTokensOfType(signSession);
            
            if (token >= 0 && tkis != null && token < tkis.size()) tki = tkis.get(token);
            
            if (LOG.isDebugEnabled())
                LOG.debug("Open "
                                + (signSession ? "sign" : "auth")
                                + " session for: "
                                + ((tki != null) ? tki.getCertName() + " id: " + tki.getIdHex() + " sign: "
                                                + tki.isSignatureKey() + " crypt: " + tki.isEncryptKey() : "NULL"));

            startSession(tki, pin);
        }
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
        byte[] signatureValue = null;
        if (currentSession == null) openSession(true, token, pin);
        
        try {
            
            if (LOG.isDebugEnabled())
                LOG.debug("Sign with token: " + token + " key: "
                                + ((selectedToken != null) ? selectedToken.getCertName() : "NULL") + " id: "
                                + ((selectedToken != null) ? selectedToken.getIdHex() : "NULL") + " dig-len: "
                                + ((digest != null) ? digest.length : 0) + " dig: "
                                + ((digest != null) ? Base64Util.encode(digest) : "NULL"));
            
            // the RSA private key object that serves as a template for searching
            RSAPrivateKey tempKey = new RSAPrivateKey();
            // initializes a find operations to find RSA private key objects
            currentSession.findObjectsInit(tempKey);
            // find first
            iaik.pkcs.pkcs11.objects.Object[] keys = null;
            
            RSAPrivateKey sigKey = null;
            boolean found = false;
            
            do {
                keys = currentSession.findObjects(1);
                if (keys != null && keys.length > 0) {
                    for (int i = 0; !found && i < keys.length; i++) {
                        sigKey = (RSAPrivateKey) keys[i];
                        String keyIdHex = ConvertUtils.bin2hex(sigKey.getId().getByteArrayValue());
                        if (LOG.isDebugEnabled()) LOG.debug("Key " + i + " id: " + keyIdHex);
                        if (keyIdHex != null && selectedToken.getIdHex() != null
                                        && keyIdHex.equals(selectedToken.getIdHex())) {
                            if (LOG.isDebugEnabled()) LOG.debug("Using key " + i + " id: " + keyIdHex);
                            found = true;
                            Mechanism sigMech = Mechanism.RSA_PKCS;
                            // initializes a new signing operation
                            currentSession.signInit(sigMech, sigKey);
                            byte[] ddata = DDUtils.addDigestAsn1Prefix(digest);
                            signatureValue = currentSession.sign(ddata); // signs the given data with the key and mechanism given to the signInit method
                            if (LOG.isDebugEnabled())
                                LOG.debug("Signature len: " + ((signatureValue != null) ? signatureValue.length : 0));
                            break;
                        }
                    }
                }
            } while (!found && keys != null && keys.length > 0);
            
            currentSession.findObjectsFinal(); // finalizes a find operation
            // close session
            closeSession();
            
        } catch (TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_SIGN);
        }
        
        return signatureValue;
    }
    
    /**
     * Method returns a digital signature. It finds the RSA private
     * key object from the active token and
     * then signs the given data with this key and RSA mechanism.
     * 
     * @param digest digest of the data to be signed.
     * @param nSlotId slot id
     * @param certLabel cert label
     * @param pin users pin code
     * @param sig Signature object to provide info about desired signature method
     * @return an array of bytes containing digital signature.
     * @throws DigiDocException if signing the data fails.
     */
    public byte[] sign(byte[] digest, long nSlotId, String certLabel, String pin, Signature sig)
                    throws DigiDocException {
        byte[] signatureValue = null;
        TokenKeyInfo tki = getTokenWithSlotIdAndLabel(nSlotId, certLabel);
        
        if (tki == null) {
            LOG.error("No token with slot: " + nSlotId + " and label: " + certLabel + " found!");
            return null;
        }
        
        if (currentSession == null) openSession(tki, pin);
        
        try {
            if (LOG.isDebugEnabled())
                LOG.debug("Sign with token: " + tki + " key: "
                                + ((selectedToken != null) ? selectedToken.getCertName() : "NULL") + " id: "
                                + ((selectedToken != null) ? selectedToken.getIdHex() : "NULL") + " dig-len: "
                                + ((digest != null) ? digest.length : 0) + " dig: "
                                + ((digest != null) ? Base64Util.encode(digest) : "NULL"));
            // the RSA private key object that serves as a template for searching
            RSAPrivateKey tempKey = new RSAPrivateKey();
            // initializes a find operations to find RSA private key objects
            currentSession.findObjectsInit(tempKey);
            // find first
            iaik.pkcs.pkcs11.objects.Object[] foundKeys = null;
            boolean found = false;
            do {
                foundKeys = currentSession.findObjects(1);

                if (foundKeys != null && foundKeys.length > 0) {
                    RSAPrivateKey sigKey = null;

                    if (LOG.isDebugEnabled()) LOG.debug("Keys: " + foundKeys.length);

                    for (int i = 0; !found && (i < foundKeys.length); i++) {
                        sigKey = (RSAPrivateKey) foundKeys[i];
                        String keyLabel = null;
                        if (sigKey.getLabel() != null) {
                            keyLabel = sigKey.getLabel().toString();
                            if (LOG.isDebugEnabled()) LOG.debug("Key " + i + " label: " + keyLabel);
                        }
                        if (keyLabel != null && selectedToken.getLabel() != null
                                        && keyLabel.equals(selectedToken.getLabel())) {
                            if (LOG.isDebugEnabled()) LOG.debug("Using key " + i + " label: " + keyLabel);
                            found = true;
                            Mechanism sigMech = Mechanism.RSA_PKCS;
                            // initializes a new signing operation
                            currentSession.signInit(sigMech, sigKey);
                            byte[] ddata = DDUtils.addDigestAsn1Prefix(digest);
                            signatureValue = currentSession.sign(ddata); // signs the given data with the key and mechanism given to the signInit method
                            if (LOG.isDebugEnabled())
                                LOG.debug("Signature len: " + ((signatureValue != null) ? signatureValue.length : 0));
                            break;
                        }
                    }
                } // if keys found
            } while (!found && foundKeys != null && foundKeys.length > 0);

            if (!found)
                LOG.error("Failed to sign, token with slot: " + nSlotId + " and label: " + certLabel + " not found!");

            currentSession.findObjectsFinal(); // finalizes a find operation
            // close session
            closeSession();
        } catch (TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_SIGN);
        }
        return signatureValue;
    }
    
    private X509Certificate getCert(boolean sign, int token, String pin) throws DigiDocException {
        if (LOG.isDebugEnabled()) LOG.debug("Get cert for token: " + token);
        if (currentSession == null) openSession(sign, token, pin);
        
        if (LOG.isDebugEnabled())
            LOG.debug("Got cert in slot: " + token + " nr: " + selectedToken.getNr() + " sign: "
                            + selectedToken.isSignatureKey() + " enc: " + selectedToken.isEncryptKey());
        if (selectedToken != null) return selectedToken.getCert();
        
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
        return getCert(true, token, pin);
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
        return getCert(false, token, pin);
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
        byte[] value = null;
        if (currentSession == null) {
            openSession(false, token, pin);
        }
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decrypting " + data.length + " bytes");
                LOG.debug("Decrypting with token: " + selectedToken.getNr());
                LOG.debug("session: " + currentSession);
            }
            RSAPrivateKey authKey = new RSAPrivateKey(); // the RSA private key object that serves as a template for searching
            currentSession.findObjectsInit(authKey); // initializes a find operations to find RSA private key objects
            iaik.pkcs.pkcs11.objects.Object[] keys = null;
            boolean found = false;
            do {
                keys = currentSession.findObjects(1);
                if (keys != null && keys.length > 0) {
                    RSAPrivateKey key = null;
                    for (int i = 0; !found && (i < keys.length); i++) {
                        key = (RSAPrivateKey) keys[i];
                        String keyIdHex = null;
                        if (key.getId() != null) {
                            keyIdHex = ConvertUtils.bin2hex(key.getId().getByteArrayValue());
                            if (LOG.isDebugEnabled()) LOG.debug("Key " + i + " id: " + keyIdHex);
                        }
                        if (keyIdHex != null && selectedToken.getIdHex() != null
                                        && keyIdHex.equals(selectedToken.getIdHex())) {
                            found = true;
                            if (LOG.isDebugEnabled()) LOG.debug("Using key " + i + " id: " + keyIdHex);
                            Mechanism m = Mechanism.RSA_PKCS;
                            currentSession.decryptInit(m, key); // initializes a new signing operation
                            if (LOG.isDebugEnabled()) LOG.debug("decryptInit OK");
                            value = currentSession.decrypt(data);
                            if (LOG.isDebugEnabled()) LOG.debug("value = " + value);
                            break;
                        }
                    }
                }
            } while (!found && keys != null && keys.length > 0);
            if (LOG.isInfoEnabled())
                LOG.info("Decrypted " + ((data != null) ? data.length : 0) + " bytes, got: " + value.length);
            currentSession.findObjectsFinal(); // finalizes a find operation
            // close session
            closeSession();
        } catch (TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_XMLENC_DECRYPT);
        }
        return value;
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
     * @param slot slot id
     * @param label token label
     * @param pin PIN code
     * @return decrypted data.
     * @throws DigiDocException for all decryption errors
     */
    public byte[] decrypt(byte[] data, long slot, String label, String pin) throws DigiDocException {
        byte[] value = null;
        TokenKeyInfo tki = getTokenWithSlotIdAndLabel(slot, label);
        if (tki == null) {
            LOG.error("No token with slot: " + slot + " and label: " + label + " found!");
            return null;
        }
        if (currentSession == null) openSession(tki, pin);
        try {
            RSAPrivateKey authKey = new RSAPrivateKey(); // the RSA private key object that serves as a template for searching
            currentSession.findObjectsInit(authKey); // initializes a find operations to find RSA private key objects
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decrypting " + data.length + " bytes");
                LOG.debug("Decrypting with token: " + selectedToken.getNr());
                LOG.debug("session: " + currentSession);
            }
            RSAPrivateKey key = null;
            boolean found = false;
            iaik.pkcs.pkcs11.objects.Object[] keys = null;
            do {
                keys = currentSession.findObjects(1);
                if (keys != null && keys.length > 0) {
                    for (int i = 0; !found && (i < keys.length); i++) {
                        key = (RSAPrivateKey) keys[i];
                        String keyLabel = null;
                        if (key.getLabel() != null) {
                            keyLabel = key.getLabel().toString();
                            if (LOG.isDebugEnabled()) LOG.debug("Key " + i + " label: " + keyLabel);
                        }
                        if (keyLabel != null && selectedToken.getLabel() != null
                                        && keyLabel.equals(selectedToken.getLabel())) {
                            if (LOG.isDebugEnabled()) LOG.debug("Using key " + i + " label: " + keyLabel);
                            found = true;
                            Mechanism m = Mechanism.RSA_PKCS;
                            currentSession.decryptInit(m, key); // initializes a new signing operation
                            if (LOG.isDebugEnabled()) LOG.debug("decryptInit OK");
                            value = currentSession.decrypt(data);
                            if (LOG.isDebugEnabled()) LOG.debug("value = " + value);
                            break;
                        }
                    }
                }
            } while (!found && keys != null && keys.length > 0);
            if (!found) LOG.error("Failed to sign, token with slot: " + slot + " and label: " + label + " not found!");
            if (LOG.isInfoEnabled())
                LOG.info("Decrypted " + ((data != null) ? data.length : 0) + " bytes, got: " + value.length);
            currentSession.findObjectsFinal(); // finalizes a find operation
            // close session
            closeSession();
        } catch (TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_XMLENC_DECRYPT);
        }
        return value;
    }
    
    /**
     * Method closes the current session.
     * 
     * @throws DigiDocException if closing the session fails.
     */
    public void closeSession() throws DigiDocException {
        try {
            if (LOG.isDebugEnabled()) LOG.debug("Closing card session");
            // closes this session
            if (currentSession != null) currentSession.closeSession();
            currentSession = null;
        } catch (TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_TOKEN_LOGOUT);
        }
    }
    
    /**
     * This finalize method tries to finalize the module
     * by calling finalize() of the PKCS#11 module.
     * 
     * @throws DigiDocException if PKCS#11 module finalization fails.
     */
    public void finalize() throws DigiDocException {
        try {
            if (pkcs11Module != null) pkcs11Module.finalize(null); // finalizes this module
            isInitialized = false;
            pkcs11Module = null;
        } catch (TokenException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_CRYPTO_FINALIZE);
        }
    }
    
    /**
     * Resets the previous session
     * and other selected values
     */
    public void reset() throws DigiDocException {
        if (LOG.isDebugEnabled()) LOG.debug("Resetting PKCS11SignatureServiceImpl");
        selectedToken = null;
        closeSession();
        finalize();
        isInitialized = false;
        pkcs11Module = null;
        securityProvider = null;
    }
    
    /**
     * Returns signature factory type identifier
     * 
     * @return factory type identifier
     */
    public String getType() {
        return SIGFAC_TYPE_PKCS11;
    }
}
