/*
 * EncryptedStreamSAXParser.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for parsing encrypted
 * data from streams. Designed to parse large encrypted
 * files. Uses PKCS#11 driver to decrypt the transport key.
 * This implementation uses SAX parser.
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
package ee.sk.digidoc.services;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Stack;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.log4j.Logger;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.TokenKeyInfo;
import ee.sk.utils.Base64Util;
import ee.sk.utils.DDUtils;
import ee.sk.xmlenc.EncryptedData;
import ee.sk.xmlenc.EncryptedKey;
import ee.sk.xmlenc.EncryptionProperty;

/**
 * Implementation class for reading and writing encrypted files using a SAX
 * parser
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class EncryptedStreamSAXParser implements EncryptedStreamParser {

    private static final Logger m_logger = Logger.getLogger(EncryptedStreamSAXParser.class);
    
    private SignatureService signatureService;
    
    /**
     * 
     * @throws DigiDocException
     */
    public EncryptedStreamSAXParser(SignatureService signatureService) throws DigiDocException {
        try {
            Provider prv = (Provider) Class.forName(EncryptedData.DIGIDOC_SECURITY_PROVIDER).newInstance();
            Security.addProvider(prv);
        } catch (Exception e) {
            DigiDocException.handleException(e, DigiDocException.ERR_NOT_FAC_INIT);
        }
        
        this.signatureService = signatureService;
    }

    /**
     * Reads in a EncryptedData file (.cdoc)
     * 
     * @param dencStream
     *            opened stream with EncrypyedData data The user must open and
     *            close it.
     * @param outs
     *            output stream for decrypted data
     * @param token
     *            index of PKCS#11 token used
     * @param pin
     *            pin code to decrypt transport key using PKCS#11
     * @param recipientName
     *            Recipient atribute value of <EncryptedKey> used to locate the
     *            correct transport key to decrypt with
     * @return number of bytes successfully decrypted
     * @throws DigiDocException
     *             for decryption errors
     */
    public int decryptStreamUsingRecipientName(InputStream dencStream, OutputStream outs, int token, String pin,
                    String recipientName) throws DigiDocException {
        
        EncodedStreamHandler handler = new EncodedStreamHandler(this.signatureService);
        handler.setRecipientName(recipientName);
        handler.setOutputStream(outs);
        handler.setPin(pin);
        handler.setToken(token);
        try {
            handler.setDecCert(signatureService.getAuthCertificate(token, pin));
        } catch (Exception ex) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "Error loading decryption cert!", null);
        }
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // factory.setNamespaceAware(true);
        try {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(dencStream, handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        
        if (handler.getEncryptedData() == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "This document is not in EncryptedData format", null);
        return handler.getTotalDecrypted();
    }
    
    /**
     * Reads in a EncryptedData file (.cdoc)
     * 
     * @param dencStream opened stream with EncrypyedData data
     *            The user must open and close it.
     * @param outs output stream for decrypted data
     * @param slot PKCS#11 slot id
     * @param label pkcs#11 token label
     * @param pin pin code to decrypt transport key using PKCS#11
     *            used to locate the correct transport key to decrypt with
     * @return number of bytes successfully decrypted
     * @throws DigiDocException for decryption errors
     */
    public int decryptStreamUsingRecipientSlotIdAndTokenLabel(InputStream dencStream, OutputStream outs, int slot,
                    String label, String pin) throws DigiDocException {
        EncodedStreamHandler handler = new EncodedStreamHandler(this.signatureService);
        handler.setOutputStream(outs);
        handler.setPin(pin);
        PKCS11SignatureServiceImpl p11SigFac = null;
        if (signatureService instanceof PKCS11SignatureServiceImpl) {
            p11SigFac = (PKCS11SignatureServiceImpl) signatureService;
        }
        if (p11SigFac == null) {
            m_logger.error("No PKCS11 signature factory");
            return 0;
        }
        signatureService = p11SigFac;
        TokenKeyInfo tki = p11SigFac.getTokenWithSlotIdAndLabel(slot, label);
        if (tki == null) {
            m_logger.error("No token with slot: " + slot + " and label: " + label);
            return 0;
        }
        if (tki != null && !tki.isEncryptKey()) {
            m_logger.error("Token with slot: " + slot + " and label: " + label + " is not an encryption key!");
            return 0;
        }
        handler.setDecCert(tki.getCert());
        handler.setTki(tki);
        if (m_logger.isDebugEnabled())
            m_logger.debug("Decrypt with slot: " + slot + " label: " + label + " token: "
                            + ((handler.getTki() != null) ? "OK" : "NULL") + " cert: "
                            + ((handler.getDecCert() != null) ? "OK" : "NULL"));
        if (handler.getDecCert() == null) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "Error loading decryption cert!", null);
        }
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        try {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(dencStream, handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (handler.getEncryptedData() == null) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "This document is not in EncryptedData format", null);
        }
        return handler.getTotalDecrypted();
    }
    
    /**
     * Reads in a EncryptedData file (.cdoc)
     * 
     * @param dencStream opened stream with EncrypyedData data The user must open and close it.
     * @param outs output stream for decrypted data
     * @param token index of PKCS#11 token used
     * @param pin pin code to decrypt transport key using PKCS#11
     * @param tokenType token type - PKCS11 or PKCS12
     * @param pkcs12Keystore - PKCS12 keystore filename and path if pkcs12 is used
     * @return number of bytes successfully decrypted
     * @throws DigiDocException for decryption errors
     */
    public int decryptStreamUsingTokenType(InputStream dencStream, OutputStream outs, int token, String pin,
                    String tokenType, String pkcs12Keystore) throws DigiDocException {
        EncodedStreamHandler handler = new EncodedStreamHandler(this.signatureService);
        handler.setOutputStream(outs);
        handler.setPin(pin);
        handler.setToken(token);
        if (tokenType == null
                        || (!tokenType.equals(SignatureService.SIGFAC_TYPE_PKCS11) && !tokenType
                                        .equals(SignatureService.SIGFAC_TYPE_PKCS12)))
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DECRYPT,
                            "Invalid token type. Must be PKCS11 or PKCS12!", null);
        // try find cert of token to decrypt with
        try {
            if (signatureService != null && signatureService instanceof PKCS12SignatureServiceImpl) {
                PKCS12SignatureServiceImpl pfac = (PKCS12SignatureServiceImpl) signatureService;
                if (m_logger.isDebugEnabled()) m_logger.debug("Loading pkcs12 keystore: " + pkcs12Keystore);
                pfac.load(pkcs12Keystore, tokenType, pin);
            }
            handler.setDecCert(signatureService.getAuthCertificate(token, pin));
        } catch (Exception ex) {
            m_logger.error("Error loading decryption cert: " + ex);
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DECRYPT, "Error loading decryption cert!", ex);
        }
        if (handler.getDecCert() == null)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DECRYPT, "Error loading decryption cert!", null);
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        try {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(dencStream, handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (handler.getEncryptedData() == null) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "This document is not in EncryptedData format", null);
        }
        return handler.getTotalDecrypted();
    }

    /**
     * Reads in a EncryptedData file (.cdoc)
     * 
     * @param dencStream
     *            opened stream with EncrypyedData data The user must open and
     *            close it.
     * @param outs
     *            output stream for decrypted data
     * @param deckey
     *            decryption key
     * @param recipientName
     *            Recipient atribute value of <EncryptedKey> used to locate the
     *            correct transport key to decrypt with
     * @return number of bytes successfully decrypted
     * @throws DigiDocException
     *             for decryption errors
     */
    public int decryptStreamUsingRecipientNameAndKey(InputStream dencStream, OutputStream outs, byte[] deckey,
                    String recipientName) throws DigiDocException {
        // Use an instance of ourselves as the SAX event handler
        EncodedStreamHandler handler = new EncodedStreamHandler(this.signatureService);
        handler.setRecipientName(recipientName);
        handler.setOutputStream(outs);
        handler.setM_transpkey(deckey);
        handler.setTransportKey((SecretKey) new SecretKeySpec(handler.getM_transpkey(),
                        EncryptedData.DIGIDOC_ENCRYPTION_ALOGORITHM));
        if (m_logger.isDebugEnabled()) {
            m_logger.debug("Transport key: " + ((handler.getTransportKey() == null) ? "ERROR" : "OK") + " len: "
                            + handler.getM_transpkey().length);
        }
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        try {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(dencStream, handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (handler.getEncryptedData() == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "This document is not in EncryptedData format", null);
        return handler.getTotalDecrypted();
    }
    
    private static class EncodedStreamHandler extends DefaultHandler {
        private Stack<String> m_tags;
        private EncryptedData encryptedData;
        private StringBuffer m_sbCollectChars;
        private TokenKeyInfo m_tki;

        private int m_totalDecrypted, m_totalDecompressed, m_totalInput;
        /** stream to write decrypted data */
        private OutputStream m_outStream;
        /** value of Recipient atribute to select the <EncryptedKey> */
        private String m_recvName;
        /** pin code used to decrypt the transport key */
        private String m_pin;
        /** index of PKCS#11 token used in decryption */
        private int m_token;
        /** transport key value */
        private byte[] m_transpkey;
        /** cipher used in decryption of data */
        private Cipher m_cipher;
        /** flag: decrypting / not decrypting */
        private boolean m_bDecrypting;
        /** decompressor */
        private Inflater m_decompressor;
        /** one single buffer */
        private StringBuffer m_sbParseBuf;
        private StringBuffer m_sbB64Buf;
        private static final int ENC_BLOCK_SIZE = 256;
        private X509Certificate m_decCert;
        private SecretKey m_transportKey;
        private int m_nBlockType;
        private static int DENC_BLOCK_FIRST = 1;
        private static int DENC_BLOCK_MIDDLE = 2;
        private static int DENC_BLOCK_LAST = 3;

        private final SignatureService signatureService;
        
        public EncodedStreamHandler(SignatureService signatureService) {
            this.signatureService = signatureService;
            
            m_tags = new Stack<String>();
            encryptedData = null;
            m_pin = null;
            m_cipher = null;
            m_outStream = null;
            m_decCert = null;
            m_recvName = null;
            m_bDecrypting = false;
            m_totalDecrypted = 0;
            m_totalDecompressed = 0;
            m_totalInput = 0;
            m_token = 0;
            m_sbCollectChars = null;
            m_decompressor = null;
            m_transportKey = null;
            m_transpkey = null;
        }
        
        /**
         * Initializes the Recipient atribute value used for locating the right
         * <EncryptedKey> to be used for deryption
         * 
         * @param s
         *            value of Recipient atribute
         */
        public void setRecipientName(String s) {
            m_recvName = s;
        }

        /**
         * Initializes the output stream where to write decrypted data
         * 
         * @param outs
         *            output stream already opened by the user
         */
        public void setOutputStream(OutputStream outs) {
            m_outStream = outs;
        }

        /**
         * Initializes the PIN code used to decrypt the transport key
         * 
         * @param pin
         *            PIN code
         */
        public void setPin(String pin) {
            m_pin = pin;
        }

        /**
         * Initializes the PKCS#11 token index used for decryption
         * 
         * @param tok
         *            PKCS#11 token index used for decryption
         */
        public void setToken(int tok) {
            m_token = tok;
        }

        public void setM_transpkey(byte[] m_transpkey) {
            this.m_transpkey = m_transpkey;
        }
        
        public byte[] getM_transpkey() {
            return m_transpkey;
        }

        public void setTransportKey(SecretKey key) {
            m_transportKey = key;
        }
        
        public SecretKey getTransportKey() {
            return m_transportKey;
        }

        public void setDecCert(X509Certificate cert) {
            m_decCert = cert;
        }
        
        public X509Certificate getDecCert() {
            return m_decCert;
        }

        public void setTki(TokenKeyInfo tki) {
            m_tki = tki;
        }
        
        public TokenKeyInfo getTki() {
            return m_tki;
        }

        /**
         * Start Document handler
         */
        public void startDocument() throws SAXException {
            encryptedData = null;
            m_sbCollectChars = null;
            m_decompressor = null;
            m_totalDecrypted = 0;
            m_totalDecompressed = 0;
            m_totalInput = 0;
            m_sbParseBuf = new StringBuffer();
            m_sbB64Buf = new StringBuffer();
            m_nBlockType = DENC_BLOCK_FIRST;
        }

        /**
         * End Document handler
         */
        public void endDocument() throws SAXException {}

        /**
         * Finds the value of an atribute by name
         * 
         * @param atts
         *            atributes
         * @param attName
         *            name of atribute
         * @return value of the atribute
         */
        private String findAtributeValue(Attributes attrs, String attName) {
            String value = null;
            for (int i = 0; i < attrs.getLength(); i++) {
                String key = attrs.getQName(i);
                if (key.equals(attName) || key.indexOf(attName) != -1) {
                    value = attrs.getValue(i);
                    break;
                }
            }
            return value;
        }

        /**
         * Checks if this document is in <EncryptedData> format
         * 
         * @throws SAXDigiDocException
         *             if the document is not in <EncryptedData> format
         */
        private void checkEncryptedData() throws SAXDigiDocException {
            if (encryptedData == null) {
                throw new SAXDigiDocException(DigiDocException.ERR_XMLENC_NO_ENCRYPTED_DATA,
                                "This document is not in EncryptedData format!");
            }
        }

        /**
         * Checks if the <EncryptedKey> objects exists
         * 
         * @throws SAXDigiDocException
         *             if the objects <EncryptedKey> does not exist
         */
        private void checkEncryptedKey(EncryptedKey key) throws SAXDigiDocException {
            if (key == null) {
                throw new SAXDigiDocException(DigiDocException.ERR_XMLENC_NO_ENCRYPTED_KEY,
                                "This <EncryptedKey> object does not exist!");
            }
        }

        /**
         * Start Element handler
         * 
         * @param namespaceURI
         *            namespace URI
         * @param lName
         *            local name
         * @param qName
         *            qualified name
         * @param attrs
         *            attributes
         */
        public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
                        throws SAXDigiDocException {
            String tName = qName;
            if (tName.indexOf(":") != -1) tName = qName.substring(qName.indexOf(":") + 1);
            if (m_logger.isDebugEnabled())
                m_logger.debug("Start Element: " + tName + " qname: " + qName + " lname: " + lName + " uri: "
                                + namespaceURI);
            m_tags.push(tName);
            if (tName.equals("KeyName") || tName.equals("CarriedKeyName") || tName.equals("X509Certificate")
                            || tName.equals("EncryptionProperty")) m_sbCollectChars = new StringBuffer();
            if (tName.equals("CipherValue")) {
                if (m_tags.search("EncryptedKey") != -1) { // child of <EncryptedKey>
                    m_sbCollectChars = new StringBuffer();
                } else { // child of <EncryptedKey>
                    m_sbCollectChars = null;
                    m_bDecrypting = true;
                }
            }
            // <EncryptedData>
            if (tName.equals("EncryptedData")) {
                String str = findAtributeValue(attrs, "xmlns");
                try {
                    encryptedData = new EncryptedData(str, this.signatureService);
                    str = findAtributeValue(attrs, "Id");
                    if (str != null) {
                        encryptedData.setId(str);
                    }
                    str = findAtributeValue(attrs, "Type");
                    if (str != null) {
                        encryptedData.setType(str);
                    }
                    str = findAtributeValue(attrs, "MimeType");
                    if (str != null) {
                        encryptedData.setMimeType(str);
                    }
                    if (encryptedData.getMimeType() != null
                                    && encryptedData.getMimeType().equals(EncryptedData.DENC_ENCDATA_MIME_ZLIB)) {
                        m_decompressor = new Inflater();
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
                try {
                    if (m_transportKey != null) {
                        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                        m_cipher = encryptedData.getCipher(Cipher.DECRYPT_MODE, m_transportKey, iv);
                    }
                } catch (DigiDocException ex) {
                    m_logger.error("Error using key: "
                                    + ((m_transpkey != null) ? Base64Util.encode(m_transpkey) : "NULL") + " - " + ex);
                    SAXDigiDocException.handleException(ex);
                }
            }
            // <EncryptionMethod>
            if (tName.equals("EncryptionMethod")) {
                checkEncryptedData();
                if (m_tags.search("EncryptedKey") != -1) { // child of <EncryptedKey>
                    EncryptedKey ekey = encryptedData.getLastEncryptedKey();
                    checkEncryptedKey(ekey);
                    try {
                        ekey.setEncryptionMethod(findAtributeValue(attrs, "Algorithm"));
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                } else { // child of <EncryptedData>
                    try {
                        encryptedData.setEncryptionMethod(findAtributeValue(attrs, "Algorithm"));
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
            }
            // <EncryptedKey>
            if (tName.equals("EncryptedKey")) {
                checkEncryptedData();
                EncryptedKey ekey = new EncryptedKey();
                encryptedData.addEncryptedKey(ekey);
                String str = findAtributeValue(attrs, "Recipient");
                if (str != null) ekey.setRecipient(str);
                str = findAtributeValue(attrs, "Id");
                if (str != null) ekey.setId(str);
            }
            // <EncryptionProperties>
            if (tName.equals("EncryptionProperties")) {
                checkEncryptedData();
                String str = findAtributeValue(attrs, "Id");
                if (str != null) encryptedData.setEncryptionPropertiesId(str);
            }
            // <EncryptionProperty>
            if (tName.equals("EncryptionProperty")) {
                checkEncryptedData();
                EncryptionProperty eprop = new EncryptionProperty();
                encryptedData.addProperty(eprop);
                String str = findAtributeValue(attrs, "Id");
                if (str != null) eprop.setId(str);
                str = findAtributeValue(attrs, "Target");
                if (str != null) eprop.setTarget(str);
                str = findAtributeValue(attrs, "Name");
                try {
                    if (str != null) eprop.setName(str);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
        }

        /**
         * End Element handler
         * 
         * @param namespaceURI
         *            namespace URI
         * @param lName
         *            local name
         * @param qName
         *            qualified name
         */
        public void endElement(String namespaceURI, String sName, String qName) throws SAXException {
            String tName = qName;
            if (tName.indexOf(":") != -1) tName = qName.substring(tName.indexOf(":") + 1);
            if (m_logger.isDebugEnabled()) m_logger.debug("End Element: " + tName);
            // remove last tag from stack
            String currTag = (String) m_tags.pop();
            // <KeyName>
            if (tName.equals("KeyName")) {
                checkEncryptedData();
                EncryptedKey ekey = encryptedData.getLastEncryptedKey();
                checkEncryptedKey(ekey);
                ekey.setKeyName(m_sbCollectChars.toString());
                m_sbCollectChars = null; // stop collecting
            }
            // <CarriedKeyName>
            if (tName.equals("CarriedKeyName")) {
                checkEncryptedData();
                EncryptedKey ekey = encryptedData.getLastEncryptedKey();
                checkEncryptedKey(ekey);
                ekey.setCarriedKeyName(m_sbCollectChars.toString());
                m_sbCollectChars = null; // stop collecting
            }
            // <X509Certificate>
            if (tName.equals("X509Certificate")) {
                checkEncryptedData();
                EncryptedKey ekey = encryptedData.getLastEncryptedKey();
                checkEncryptedKey(ekey);
                try {
                    X509Certificate cert = DDUtils.readCertificate(Base64Util.decode(m_sbCollectChars.toString()
                                    .getBytes()));
                    ekey.setRecipientsCertificate(cert);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
                m_sbCollectChars = null; // stop collecting
            }
            // <CipherValue>
            if (tName.equals("CipherValue")) {
                checkEncryptedData();
                if (m_tags.search("EncryptedKey") != -1) { // child of <EncryptedKey>
                    if (m_cipher == null) { // if transport key has not been found yet
                        EncryptedKey ekey = encryptedData.getLastEncryptedKey();
                        checkEncryptedKey(ekey);
                        ekey.setTransportKeyData(Base64Util.decode(m_sbCollectChars.toString().getBytes()));
                        // decrypt transport key if possible
                        if (m_logger.isDebugEnabled()) {
                            m_logger.debug("Recipient: " + ekey.getRecipient() + " cert-nr: "
                                            + ekey.getRecipientsCertificate().getSerialNumber() + " decrypt-cert: "
                                            + m_decCert.getSerialNumber());
                        }
                        if (m_decCert != null
                                        && ekey.getRecipientsCertificate() != null
                                        && m_decCert.getSerialNumber().equals(
                                                        ekey.getRecipientsCertificate().getSerialNumber())) {
                            // decrypt transport key
                            byte[] decdata = null;
                            
                            if (signatureService == null) {
                                DigiDocException ex2 = new DigiDocException(DigiDocException.ERR_XMLENC_KEY_DECRYPT,
                                                "SignatureFactory not initialized!", null);
                                SAXDigiDocException.handleException(ex2);
                            }
                            
                            try {
                                
                                if (m_logger.isDebugEnabled())
                                    m_logger.debug("Decrypting key: " + m_recvName + " serial: "
                                                    + m_decCert.getSerialNumber());
                                
                                if (m_transpkey != null) {
                                    decdata = m_transpkey;
                                } else if (m_tki != null) {
                                    decdata = ((PKCS11SignatureServiceImpl) signatureService).decrypt(
                                                    ekey.getTransportKeyData(), m_tki.getSlotId(), m_tki.getLabel(),
                                                    m_pin);
                                } else {
                                    decdata = signatureService.decrypt(ekey.getTransportKeyData(), m_token, m_pin);
                                }
                                
                                if (m_logger.isDebugEnabled()) {
                                    m_logger.debug("Using key: " + m_recvName + " decdata: "
                                                    + Base64Util.encode(decdata));
                                }
                                
                                m_transportKey = (SecretKey) new SecretKeySpec(decdata,
                                                EncryptedData.DIGIDOC_ENCRYPTION_ALOGORITHM);
                                byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                                m_cipher = encryptedData.getCipher(Cipher.DECRYPT_MODE, m_transportKey, iv);
                                
                                if (m_logger.isDebugEnabled()) {
                                    m_logger.debug("Transport key: " + ((m_transportKey == null) ? "ERROR" : "OK")
                                                    + " len: " + decdata.length);
                                }
                            } catch (DigiDocException ex) {
                                m_logger.error("Error decrypting key1: "
                                                + ((decdata != null) ? Base64Util.encode(decdata) : "NULL") + " - "
                                                + ex);
                                SAXDigiDocException.handleException(ex);
                            } catch (Exception ex) {
                                m_logger.error("Error decrypting key2: "
                                                + ((decdata != null) ? Base64Util.encode(decdata) : "NULL") + " - "
                                                + ex);
                                DigiDocException ex2 = new DigiDocException(DigiDocException.ERR_XMLENC_KEY_DECRYPT,
                                                ex.getMessage(), ex);
                                SAXDigiDocException.handleException(ex2);
                            }
                        }
                    }
                } else { // child of <EncryptedData>
                    m_bDecrypting = false;
                    decryptBlock(null, DENC_BLOCK_LAST);
                    if (m_logger.isInfoEnabled())
                        m_logger.info("Total input: " + m_totalInput + " decrypted: " + m_totalDecrypted
                                        + " decompressed: " + m_totalDecompressed);
                }
                m_sbCollectChars = null; // stop collecting
            }
            // <EncryptionProperty>
            if (tName.equals("EncryptionProperty")) {
                checkEncryptedData();
                EncryptionProperty eprop = encryptedData.getLastProperty();
                try {
                    eprop.setContent(m_sbCollectChars.toString());
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
                m_sbCollectChars = null; // stop collecting
            }

        }
        
        private byte[] m_lblock = null;
        private static final int DECBLOCK_SIZE = 8 * 1024;

        /**
         * Called with a block of base64 data that must be decoded, decrypted and possibly also decompressed
         * 
         * @param data base64 encoded input data
         * @param nBlockType type of block (first, middle, last)
         * 
         * @throws SAXException
         */
        private void decryptBlock(String data, int nBlockType) throws SAXException {
            // append new data to parse buffer
            if (data != null && data.length() > 0) {
                m_sbParseBuf.append(data);
            }
            String indata = null;
            if (nBlockType == DENC_BLOCK_LAST) {
                indata = m_sbParseBuf.toString();
            } else {
                if (m_sbParseBuf.length() > ENC_BLOCK_SIZE) {
                    indata = m_sbParseBuf.substring(0, ENC_BLOCK_SIZE);
                    m_sbParseBuf.delete(0, ENC_BLOCK_SIZE);
                }
            }
            if (m_logger.isDebugEnabled()) {
                m_logger.debug("IN " + ((data != null) ? data.length() : 0) + " input: "
                                + ((indata != null) ? indata.length() : 0) + " buffered: "
                                + ((m_sbParseBuf != null) ? m_sbParseBuf.length() : 0) + " b64left: "
                                + ((m_sbB64Buf != null) ? m_sbB64Buf.length() : 0) + " block-type: " + nBlockType);
            }
            // check that cipher has been initialized
            if (m_cipher == null) {
                DigiDocException de = new DigiDocException(DigiDocException.ERR_XMLENC_DECRYPT,
                                "Cipher has not been initialized! No transport key for selected recipient?", null);
                SAXDigiDocException.handleException(de);
            }
            // add to data to be b64 decoded
            if (indata != null) {
                m_sbB64Buf.append(indata);
                m_totalInput += indata.length();
            } else {
                return;
            }
            try {
                byte[] encdata = null;
                byte[] decdata = null;
                // decode base64
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                int nUsed = 0;
                if (m_sbB64Buf.length() > 0) {
                    nUsed = Base64Util.decodeBlock(m_sbB64Buf.toString(), bos, nBlockType == DENC_BLOCK_LAST);
                    encdata = bos.toByteArray();
                    // get the cipher if first block of data
                    if (nBlockType == DENC_BLOCK_FIRST && encdata != null && encdata.length > 16) { // skip IV on first block
                        byte[] b1 = new byte[encdata.length - 16];
                        System.arraycopy(encdata, 16, b1, 0, b1.length);
                        if (m_logger.isDebugEnabled()) {
                            m_logger.debug("Removed IV from: " + encdata.length + " block1, left: " + b1.length);
                        }
                        encdata = b1;
                    }
                    bos = null;
                    if (m_logger.isDebugEnabled()) {
                        m_logger.debug("Decoding: " + m_sbB64Buf.length() + " got: "
                                        + ((encdata != null) ? encdata.length : 0) + " last: "
                                        + (nBlockType == DENC_BLOCK_LAST));
                    }
                    if (nUsed > 0) {
                        m_sbB64Buf.delete(0, nUsed);
                    }
                }
                // decrypt the data
                decdata = m_cipher.update(encdata);
                if (m_logger.isDebugEnabled()) {
                    m_logger.debug("Decrypted input: " + ((indata != null) ? indata.length() : 0) + " decoded: "
                                    + ((encdata != null) ? encdata.length : 0) + " decrypted: "
                                    + ((decdata != null) ? decdata.length : 0));
                }
                if (m_totalDecrypted == 0 && decdata != null && decdata.length > 16) {
                    byte[] ddata = new byte[decdata.length - 16];
                    System.arraycopy(decdata, 16, ddata, 0, decdata.length - 16);
                    if (m_logger.isDebugEnabled()) {
                        m_logger.debug("Removing IV data from: " + decdata.length + " remaining: " + ddata.length);
                    }
                    decdata = ddata;
                }
                // padding check on last and before-last block
                if (nBlockType == DENC_BLOCK_LAST) {
                    int n1 = ((m_lblock != null) ? m_lblock.length : 0);
                    int n2 = ((decdata != null) ? decdata.length : 0);
                    byte[] ddata = new byte[n1 + n2];
                    if (n1 > 0) {
                        System.arraycopy(m_lblock, 0, ddata, 0, n1);
                    }
                    if (n2 > 0) {
                        System.arraycopy(decdata, 0, ddata, n1, n2);
                    }
                    decdata = ddata;
                    if (m_logger.isDebugEnabled()) {
                        m_logger.debug("Last block: " + ((decdata != null) ? decdata.length : 0));
                    }
                    m_lblock = null;
                }
                // remove padding on the last block
                if (decdata != null && encdata != null && nBlockType == DENC_BLOCK_LAST) {
                    int nPadLen = new Integer(decdata[decdata.length - 1]).intValue();
                    if (m_logger.isDebugEnabled()) {
                        m_logger.debug("Check padding 1: " + nPadLen);
                    }
                    boolean bPadOk = checkPadding(decdata, nPadLen);
                    if (bPadOk) {
                        decdata = removePadding(decdata, nPadLen);
                    }
                    if (m_logger.isDebugEnabled()) {
                        m_logger.debug("Decdata remaining: " + ((decdata != null) ? decdata.length : 0));
                    }
                    // second padding
                    if (decdata != null && decdata.length > 0) {
                        nPadLen = new Integer(decdata[decdata.length - 1]).intValue();
                        if (m_logger.isDebugEnabled()) {
                            m_logger.debug("Check padding 2: " + nPadLen);
                        }
                        if (nPadLen > 0 && nPadLen <= 16 && decdata.length > nPadLen) {
                            bPadOk = checkPadding(decdata, nPadLen);
                            if (bPadOk) {
                                decdata = removePadding(decdata, nPadLen);
                            }
                        }
                    } else if (m_lblock != null) {
                        nPadLen = new Integer(m_lblock[m_lblock.length - 1]).intValue();
                        if (m_logger.isDebugEnabled()) {
                            m_logger.debug("Check padding 3: " + nPadLen);
                        }
                        if (nPadLen > 0 && nPadLen <= 16 && m_lblock.length > nPadLen) {
                            bPadOk = checkPadding(m_lblock, nPadLen);
                            if (bPadOk) {
                                m_lblock = removePadding(m_lblock, nPadLen);
                            }
                        }
                    }
                }

                // decompress if necessary and write to output stream
                if (m_lblock != null || decdata != null) {
                    // check compression
                    if (m_decompressor != null) {
                        if (nBlockType == DENC_BLOCK_LAST) {
                            m_lblock = decdata;
                        }
                        int nDecomp = 0;
                        byte[] m_decbuf = null;
                        if (m_lblock != null) {
                            if (m_logger.isDebugEnabled()) {
                                m_logger.debug("Decompressing: " + m_lblock.length);
                            }
                            m_decompressor.setInput(m_lblock);
                            m_decbuf = new byte[DECBLOCK_SIZE];
                            if (m_logger.isDebugEnabled()) {
                                m_logger.debug("Decompressing: " + m_lblock.length + " into: " + m_decbuf.length);
                            }
                            while ((nDecomp = m_decompressor.inflate(m_decbuf)) > 0) {
                                if (m_logger.isDebugEnabled()) {
                                    m_logger.debug("Decompressed: " + m_lblock.length + " into: " + m_decbuf.length
                                                    + " got: " + nDecomp);
                                }
                                m_outStream.write(m_decbuf, 0, nDecomp);
                                m_totalDecompressed += nDecomp;
                            }
                        }
                        if (nBlockType == DENC_BLOCK_LAST
                                        && (!m_decompressor.finished() || m_decompressor.getRemaining() > 0)) {
                            if (m_logger.isDebugEnabled()) {
                                m_logger.debug("Decompressor finished: " + m_decompressor.finished() + " remaining: "
                                                + m_decompressor.getRemaining());
                            }
                            m_decbuf = new byte[1024 * 8];
                            while ((nDecomp = m_decompressor.inflate(m_decbuf)) > 0) {
                                m_outStream.write(m_decbuf, 0, nDecomp);
                                m_totalDecompressed += nDecomp;
                                if (m_logger.isDebugEnabled()) {
                                    m_logger.debug("Decompressing final: " + nDecomp);
                                }
                            }
                        }
                    } else { // not compressed
                        if (m_lblock != null) { // second block is first to be written
                            m_outStream.write(m_lblock);
                        }
                        if (nBlockType == DENC_BLOCK_LAST && decdata != null) {// write also last block
                            m_outStream.write(decdata);
                        }
                    }
                    m_totalDecrypted += decdata.length;
                }
                // keep last block for possible padding check
                m_lblock = decdata;
            } catch (Exception ex) {
                DigiDocException de = new DigiDocException(DigiDocException.ERR_XMLENC_DECRYPT, "Error decrypting: "
                                + ex, ex);
                SAXDigiDocException.handleException(de);
            }
        }
        
        private boolean checkPadding(byte[] data, int nPadLen) {
            boolean bPadOk = true;
            if (m_logger.isDebugEnabled()) {
                m_logger.debug("Checking padding: " + nPadLen + " bytes");
            }
            if (nPadLen < 0 || nPadLen > 16 || data == null || data.length < nPadLen) {
                return false;
            }
            for (int i = data.length - nPadLen; nPadLen > 0 && i < data.length - 1; i++) {
                if (m_logger.isDebugEnabled()) {
                    m_logger.debug("Data at: " + i + " = " + data[i]);
                }
                if ((data[i] != 0 && nPadLen != 16) || (nPadLen == 16 && data[i] != 16 && data[i] != 0)) {
                    if (m_logger.isDebugEnabled()) {
                        m_logger.debug("Data at: " + i + " = " + data[i] + " cancel padding");
                    }
                    bPadOk = false;
                    break;
                }
            }
            return bPadOk;
        }
        
        private byte[] removePadding(byte[] data, int nPadLen) {
            if (m_logger.isDebugEnabled()) {
                m_logger.debug("Removing padding: " + nPadLen + " bytes");
            }
            if (nPadLen < 0 || nPadLen > 16 || data == null || data.length < nPadLen) {
                return data;
            }
            byte[] data2 = new byte[data.length - nPadLen];
            System.arraycopy(data, 0, data2, 0, data.length - nPadLen);
            return data2;
        }

        /**
         * SAX characters event handler
         * 
         * @param buf
         *            received bytes array
         * @param offset
         *            offset to the array
         * @param len
         *            length of data
         */
        public void characters(char buf[], int offset, int len) throws SAXException {
            String s = new String(buf, offset, len);
            // just collect the data since it could be on many lines and be processed in many events
            if (s != null) {
                if (m_sbCollectChars != null) m_sbCollectChars.append(s);
                if (m_bDecrypting) {
                    decryptBlock(s, m_nBlockType);
                    if (m_nBlockType == DENC_BLOCK_FIRST) m_nBlockType = DENC_BLOCK_MIDDLE;
                }
            }
        }
        
        public int getTotalDecrypted() {
            return m_totalDecrypted;
        }
        
        public EncryptedData getEncryptedData() {
            return encryptedData;
        }
    }

}
