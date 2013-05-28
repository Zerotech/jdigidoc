package ee.sk.digidoc.services;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Stack;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.log4j.Logger;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import ee.sk.digidoc.CertID;
import ee.sk.digidoc.CertValue;
import ee.sk.digidoc.CompleteCertificateRefs;
import ee.sk.digidoc.CompleteRevocationRefs;
import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DataFileAttribute;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.IncludeInfo;
import ee.sk.digidoc.KeyInfo;
import ee.sk.digidoc.Notary;
import ee.sk.digidoc.OcspRef;
import ee.sk.digidoc.Reference;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignatureProductionPlace;
import ee.sk.digidoc.SignatureValue;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.SignedInfo;
import ee.sk.digidoc.SignedProperties;
import ee.sk.digidoc.TimestampInfo;
import ee.sk.digidoc.UnsignedProperties;
import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;

public class SAXDigidocServiceImpl implements DigiDocService {

    private static final Logger LOG = Logger.getLogger(SAXDigidocServiceImpl.class);

    private final CanonicalizationService canonicalizationService;
    
    private final NotaryService notaryService;
    
    private final TimestampService timestampService;
    
    public static final String FILE_MIMETYPE = "mimetype";
    public static final String FILE_MANIFEST = "manifest.xml";
    public static final String CONTENTS_MIMETYPE = "application/vnd.bdoc";
    
    public SAXDigidocServiceImpl(CanonicalizationService canonicalizationService, NotaryService notaryService,
                    TimestampService timestampService) {
        this.canonicalizationService = canonicalizationService;
        this.notaryService = notaryService;
        this.timestampService = timestampService;
    }
    
    private void initProvider() {
        try {
            Provider prv = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
            Security.addProvider(prv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Checks if this stream could be a bdoc input stream
     * 
     * @param is input stream, must support mark() and reset() operations!
     * @return true if bdoc
     */
    private boolean isBdocFile(InputStream is) throws DigiDocException {
        try {
            if (is.markSupported()) is.mark(10);
            byte[] tdata = new byte[10];
            int n = is.read(tdata);
            if (is.markSupported()) is.reset();
            if (n >= 2 && tdata[0] == (byte) 'P' && tdata[1] == (byte) 'K') return true; // probably a zip file
            if (n >= 5 && tdata[0] == (byte) '<' && tdata[1] == (byte) '?' && tdata[2] == (byte) 'x'
                            && tdata[3] == (byte) 'm' && tdata[4] == (byte) 'l') return false; // an xml file - probably ddoc format?
        } catch (Exception ex) {
            LOG.error("Error determining file type: " + ex);
        }
        return false;
    }
    
    /**
     * Reads in a DigiDoc or BDOC file
     * 
     * @param fileName file name
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fileName) throws DigiDocException {
        try {
            FileInputStream fis = new FileInputStream(fileName);
            boolean bdoc = isBdocFile(fis);
            fis.close();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Reading in " + (bdoc ? "bdoc" : "ddoc") + " from file!");
            }
            return readSignedDocOfType(fileName, null, bdoc);
        } catch (FileNotFoundException e) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE, "File not found: " + fileName, null);
        } catch (IOException e) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE, "Error determning file type: " + fileName, null);
        } catch (NullPointerException e) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE, "File is not set: " + fileName, null);
        }

    }
    
    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * 
     * @param digiDocStream opened stream with DigiDoc/BDOC data
     *            The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocFromStream(InputStream digiDocStream) throws DigiDocException {
        boolean bdoc = isBdocFile(digiDocStream);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Reading in " + (bdoc ? "bdoc" : "ddoc") + " from stream!");
        }
        return readSignedDocOfType(null, digiDocStream, bdoc);
    }
    
    private SignedDoc readSignedDocOfType(String fileName, InputStream stream, boolean isBdoc) throws DigiDocException {

        DDHandler handler = new DDHandler();
        SAXParserFactory factory = SAXParserFactory.newInstance();
        initProvider();
        
        if (LOG.isDebugEnabled())
            LOG.debug("Start reading ddoc/bdoc " + ((fileName != null) ? "from file: " + fileName : "from stream"));
        if (fileName == null && stream == null) {
            throw new DigiDocException(DigiDocException.ERR_READ_FILE, "No input file", null);
        }
        
        try {
            
            if (isBdoc) { // bdoc parsing
                handler.setSignedDoc(new SignedDoc(SignedDoc.FORMAT_BDOC, SignedDoc.VERSION_1_0));

                ZipFile zf = null;
                ZipArchiveInputStream zis = null;
                ZipArchiveEntry ze = null;
                Enumeration<ZipArchiveEntry> eFiles = null;
                
                if (fileName != null) {
                    zf = new ZipFile(fileName, "UTF-8");
                    eFiles = zf.getEntries();
                } else if (stream != null) {
                    zis = new ZipArchiveInputStream(stream, "UTF-8", true, true);
                }
                
                // read all entries
                while ((zf != null && eFiles.hasMoreElements())
                                || (zis != null && ((ze = zis.getNextZipEntry()) != null))) {
                    InputStream isEntry = null;
                    
                    // read entry
                    if (zf != null) { // ZipFile
                        ze = eFiles.nextElement();
                        isEntry = zf.getInputStream(ze);
                    } else { // ZipArchiveInputStream
                        int n = 0, nTot = 0;
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        byte[] data = new byte[2048];
                        while ((n = zis.read(data)) > 0) {
                            bos.write(data, 0, n);
                            nTot += n;
                        }
                        if (LOG.isDebugEnabled()) LOG.debug("Read: " + nTot + " bytes from zip");
                        data = bos.toByteArray();
                        bos = null;
                        isEntry = new ByteArrayInputStream(data);
                    }
                    
                    if (LOG.isDebugEnabled())
                        LOG.debug("Entry: " + ze.getName() + " nlen: " + ze.getName().length() + " size: "
                                        + ze.getSize() + " dir: " + ze.isDirectory());
                    
                    // mimetype file
                    if (ze.getName().equals(FILE_MIMETYPE)) {
                        checkBdocMimetype(isEntry, handler);
                    } else if (ze.getName().indexOf(FILE_MANIFEST) != -1) { // manifest.xml file
                        BdocManifestParser mfparser = new BdocManifestParser(handler.getSignedDoc());
                        mfparser.readManifest(isEntry);
                    } else if (ze.getName().indexOf("signature") != -1 && ze.getName().endsWith(".xml")) { // some signature
                        handler.setFileName(ze.getName());
                        if (LOG.isDebugEnabled()) LOG.debug("Reading bdoc: " + handler.getFileName());
                        SAXParser saxParser = factory.newSAXParser();
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        int n = 0;
                        byte[] data = new byte[2048];
                        while ((n = isEntry.read(data)) > 0)
                            bos.write(data, 0, n);
                        data = bos.toByteArray();
                        bos = null;
                        if (LOG.isDebugEnabled())
                            LOG.debug("Parsing bdoc: " + handler.getFileName() + " size: "
                                            + ((data != null) ? data.length : 0));
                        saxParser.parse(new SignatureInputStream(new ByteArrayInputStream(data)), handler);
                        if (LOG.isDebugEnabled()) LOG.debug("Parsed bdoc: " + handler.getFileName());
                        Signature sig1 = handler.getSignedDoc().getLastSignature();
                        if (sig1 != null) sig1.setPath(handler.getFileName());
                    } else { // probably a data file
                        if (!ze.isDirectory()) {
                            DataFile df = handler.getSignedDoc().findDataFileById(ze.getName());
                            if (df != null) {
                                if (ze.getSize() > 0) df.setSize(ze.getSize());
                                df.setContentType(DataFile.CONTENT_BINARY);
                                df.setFileName(ze.getName());
                            } else {
                                df = new DataFile(ze.getName(), DataFile.CONTENT_BINARY, ze.getName(),
                                                "application/binary", handler.getSignedDoc());
                                handler.getSignedDoc().addDataFile(df);
                            }
                            // enable caching if requested
                            df.setOrCacheBodyAndCalcHashes(isEntry);
                        }
                    }
                }

            } else { // ddoc parsing
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Reading ddoc");
                }
                handler.setFileName(fileName);
                SAXParser saxParser = factory.newSAXParser();
                if (fileName != null) {
                    saxParser.parse(new SignatureInputStream(new FileInputStream(fileName)), handler);
                } else if (stream != null) {
                    saxParser.parse(new SignatureInputStream(stream), handler);
                }
            }
        } catch (Exception ex) {
            LOG.error("Error reading3: " + ex);
            if (ex instanceof DigiDocException) {
                throw (DigiDocException) ex;
            } else if (ex instanceof SAXDigiDocException) {
                throw ((SAXDigiDocException) ex).getDigiDocException();
            } else {
                new DigiDocException(DigiDocException.ERR_PARSE_XML, "Invalid xml file!", ex);
            }
        }
        
        if (handler.getSignedDoc() == null) {
            LOG.error("Error reading4: doc == null");
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "This document is not in ddoc or bdoc format", null);
        }

        return handler.getSignedDoc();
    }

    /**
     * Reads in only one <Signature>
     * 
     * @param sdoc SignedDoc to add this signature to
     * @param sigStream opened stream with Signature data
     *            The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public Signature readSignature(SignedDoc sdoc, InputStream sigStream) throws DigiDocException {
        DDHandler handler = new DDHandler();
        SAXParserFactory factory = SAXParserFactory.newInstance();
        handler.setSignedDoc(sdoc);
        handler.setCollectionMode(0);
        try {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(new SignatureInputStream(sigStream), handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (handler.getSignedDoc().getLastSignature() == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "This document is not in Signature format",
                            null);
        return handler.getSignedDoc().getLastSignature();
    }

    /**
     * Checks if this file contains the correct bdoc mimetype
     * 
     * @param zis ZIP input stream
     * @return true if correct bdoc
     */
    private boolean checkBdocMimetype(InputStream zis, DDHandler handler) throws DigiDocException {
        try {
            SignedDoc doc = handler.getSignedDoc();
            byte[] data = new byte[100];
            int nRead = zis.read(data);
            if (nRead >= CONTENTS_MIMETYPE.length()) {
                byte[] data2 = new byte[nRead];
                System.arraycopy(data, 0, data2, 0, nRead);
                String s = new String(data2);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("MimeType: \'" + s + "\'");
                }
                if (s.trim().equals(SignedDoc.MIMET_FILE_CONTENT_10)) {
                    doc.setVersion(SignedDoc.VERSION_1_0);
                    doc.setFormat(SignedDoc.FORMAT_BDOC);
                    handler.setSignedDoc(doc);
                    return true;
                } else if (s.trim().equals(SignedDoc.MIMET_FILE_CONTENT_11)) {
                    doc.setVersion(SignedDoc.VERSION_1_1);
                    doc.setFormat(SignedDoc.FORMAT_BDOC);
                    handler.setSignedDoc(doc);
                    return true;
                } else if (s.trim().startsWith(CONTENTS_MIMETYPE)) {
                    throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "Invalid BDOC version!", null);
                } else { // no bdoc or wrong version
                    if (LOG.isDebugEnabled())
                        LOG.debug("Invalid MimeType: \'" + s + "\'" + " len: " + s.length() + " expecting: "
                                        + CONTENTS_MIMETYPE.length());
                    throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "Not a BDOC format file!", null);
                }
            }
        } catch (DigiDocException ex) {
            LOG.error("Mimetype err: " + ex);
            throw ex;
        } catch (Exception ex) {
            LOG.error("Error reading mimetype file: " + ex);
        }
        return false;
    }

    class DDHandler extends DefaultHandler {
        private Stack<String> m_tags = new Stack<String>();
        private SignedDoc doc;
        private Signature sig;
        private String m_strSigValTs, m_strSigAndRefsTs;
        private StringBuffer m_sbCollectChars;
        private StringBuffer m_sbCollectItem;
        private StringBuffer m_sbCollectSignature;
        private boolean m_bCollectDigest;
        private String m_xmlnsAttr;
        private String m_fileName;
        private String m_nsDsPref;
        private String m_nsXadesPref;
        
        /**
         * This mode means collect SAX events into xml data
         * and is used to collect all <DataFile>, <SignedInfo> and
         * <SignedProperties> content. Also servers as level of
         * embedded DigiDoc files. Initially it should be 0. If
         * we start collecting data then it's 1 and if we find
         * another SignedDoc inside a DataFile then it will be incremented
         * in order to know which is the correct </DataFile> tag to leave
         * the collect mode
         */
        private int m_nCollectMode;

        /** calculation of digest */
        private MessageDigest m_digest;
        /** temp output stream used to cache DataFile content */
        private FileOutputStream dataFileCacheOutStream;
        
        public SignedDoc getSignedDoc() {
            return doc;
        }
        
        public void setSignedDoc(SignedDoc doc) {
            this.doc = doc;
        }
        
        public void setCollectionMode(int mode) {
            this.m_nCollectMode = mode;
        }
        
        public String getFileName() {
            return this.m_fileName;
        }

        public void setFileName(String fileName) {
            this.m_fileName = fileName;
        }

        public void startDocument() throws SAXException {
            if (LOG.isTraceEnabled()) {
                LOG.trace("startDocument");
            }
            
            m_nCollectMode = 0;
            m_xmlnsAttr = null;
            dataFileCacheOutStream = null;
            m_nsDsPref = null;
            m_nsXadesPref = null;
        }
        
        public void endDocument() throws SAXException {
            if (LOG.isTraceEnabled()) {
                LOG.trace("endDocument");
            }
        }
        
        private String findNsPrefForUri(Attributes attrs, String uri) {
            for (int i = 0; i < attrs.getLength(); i++) {
                String key = attrs.getQName(i);
                String val = attrs.getValue(i);
                if (val.equals(uri)) {
                    int p = key.indexOf(':');
                    if (p > 0)
                        return key.substring(p + 1);
                    else
                        return null;
                }
            }
            return null;
        }

        public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
                        throws SAXDigiDocException {

            if (LOG.isTraceEnabled()) {
                LOG.trace("Start Element: " + qName + " lname: " + lName + " uri: " + namespaceURI);
            }
            
            String tag = qName;
            if (tag.indexOf(':') != -1) {
                tag = qName.substring(qName.indexOf(':') + 1);
                if (m_nsDsPref == null) {
                    m_nsDsPref = findNsPrefForUri(attrs, xmlnsDs);
                    if (LOG.isDebugEnabled())
                        LOG.debug("Element: " + qName + " xmldsig pref: "
                                        + ((m_nsDsPref != null) ? m_nsDsPref : "NULL"));
                }
                if (m_nsXadesPref == null) {
                    m_nsXadesPref = findNsPrefForUri(attrs, xmlnsEtsi);
                    if (LOG.isDebugEnabled())
                        LOG.debug("Element: " + qName + " xades pref: "
                                        + ((m_nsXadesPref != null) ? m_nsXadesPref : "NULL"));
                }
            }
            m_tags.push(qName);
            
            if (tag.equals("SigningTime")
                            || tag.equals("IssuerSerial")
                            || tag.equals("X509SerialNumber")
                            || tag.equals("X509IssuerName")
                            || tag.equals("ClaimedRole")
                            || tag.equals("City")
                            || tag.equals("StateOrProvince")
                            || tag.equals("CountryName")
                            || tag.equals("PostalCode")
                            || tag.equals("SignatureValue")
                            || tag.equals("DigestValue")
                            || tag.equals("IssuerSerial")
                            || (tag.equals("ResponderID") && !doc.getFormat().equals(SignedDoc.FORMAT_BDOC) && !doc
                                            .getFormat().equals(SignedDoc.FORMAT_XADES))
                            || (tag.equals("ByName") && (doc.getFormat().equals(SignedDoc.FORMAT_BDOC) || doc
                                            .getFormat().equals(SignedDoc.FORMAT_XADES)))
                            || (tag.equals("ByKey") && (doc.getFormat().equals(SignedDoc.FORMAT_BDOC) || doc
                                            .getFormat().equals(SignedDoc.FORMAT_XADES)))
                            || tag.equals("X509SerialNumber") || tag.equals("ProducedAt")
                            || tag.equals("EncapsulatedTimeStamp") || tag.equals("EncapsulatedOCSPValue")) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Start collecting tag: " + tag);
                }
                m_sbCollectItem = new StringBuffer();
            }
            // <X509Certificate>
            // Prepare CertValue object
            if (tag.equals("X509Certificate")) {
                Signature sig = getLastSignature();
                CertValue cval = null;
                try {
                    if (LOG.isTraceEnabled()) LOG.trace("Adding signers cert to: " + sig.getId());
                    cval = sig.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
                m_sbCollectItem = new StringBuffer();
            }
            
            // <EncapsulatedX509Certificate>
            // Prepare CertValue object and record it's id
            if (tag.equals("EncapsulatedX509Certificate")) {
                Signature sig = getLastSignature();
                String id = null;
                for (int i = 0; i < attrs.getLength(); i++) {
                    String key = attrs.getQName(i);
                    if (key.equalsIgnoreCase("Id")) {
                        id = attrs.getValue(i);
                    }
                }
                CertValue cval = new CertValue();
                if (id != null) {
                    cval.setId(id);
                    try {
                        if (id.indexOf("RESPONDER_CERT") != -1 || id.indexOf("RESPONDER-CERT") != -1)
                            cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                if (LOG.isTraceEnabled())
                    LOG.trace("Adding cval " + cval.getId() + " type: " + cval.getType() + " to: " + sig.getId());
                sig.addCertValue(cval);
                m_sbCollectItem = new StringBuffer();
            }

            // the following elements switch collect mode
            // in and out
            // <DataFile>
            if (tag.equals("DataFile")) {
                String ContentType = null, Filename = null, Id = null, MimeType = null, Size = null, DigestType = null, Codepage = null;
                byte[] DigestValue = null;
                m_digest = null; // init to null
                if (doc != null && doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)
                                && doc.getVersion().equals(SignedDoc.VERSION_1_3))
                    m_xmlnsAttr = SignedDoc.XMLNS_DIGIDOC;
                else
                    m_xmlnsAttr = null;
                ArrayList<DataFileAttribute> dfAttrs = new ArrayList<DataFileAttribute>();
                for (int i = 0; i < attrs.getLength(); i++) {
                    String key = attrs.getQName(i);

                    if (key.equals("ContentType")) {
                        ContentType = attrs.getValue(i);
                    } else if (key.equals("Filename")) {
                        Filename = attrs.getValue(i);
                    } else if (key.equals("Id")) {
                        Id = attrs.getValue(i);
                    } else if (key.equals("MimeType")) {
                        MimeType = attrs.getValue(i);
                    } else if (key.equals("Size")) {
                        Size = attrs.getValue(i);
                    } else if (key.equals("DigestType")) {
                        DigestType = attrs.getValue(i);
                    } else if (key.equals("Codepage")) {
                        Codepage = attrs.getValue(i);
                    } else if (key.equals("DigestValue")) {
                        DigestValue = Base64Util.decode(attrs.getValue(i));
                    } else {
                        try {
                            if (!key.equals("xmlns")) {
                                DataFileAttribute attr = new DataFileAttribute(key, attrs.getValue(i));
                                dfAttrs.add(attr);
                            }
                        } catch (DigiDocException ex) {
                            SAXDigiDocException.handleException(ex);
                        }
                    } // else
                } // for
                
                if (m_nCollectMode == 0) {
                    try {
                        DataFile df = new DataFile(Id, ContentType, Filename, MimeType, doc);
                        dataFileCacheOutStream = null; // default is don't use cache file
                        
                        if (Size != null) {
                            df.setSize(Long.parseLong(Size));
                        }

                        if (DigestType != null) {
                            df.setDigestType(DigestType);
                        }

                        if (DigestValue != null) {
                            if (doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                                df.setAltDigest(DigestValue);
                            } else {
                                df.setDigestValue(DigestValue);
                            }
                        }

                        if (Codepage != null) {
                            df.setCodepage(Codepage);
                        }

                        for (int i = 0; i < dfAttrs.size(); i++) {
                            df.addAttribute((DataFileAttribute) dfAttrs.get(i));
                        }

                        // enable caching if requested
                        if (df.schouldUseTempFile()) {
                            File fCache = df.createCacheFile();
                            
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("Datafile cache enabled, Id: " + Id + " size: " + df.getSize()
                                                + " cache-file: " + fCache.getAbsolutePath());
                            }
                            df.setCacheFile(fCache);
                            dataFileCacheOutStream = new FileOutputStream(fCache);
                        }
                        
                        doc.addDataFile(df);
                    } catch (IOException ex) {
                        SAXDigiDocException.handleException(ex);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
                m_nCollectMode++;
                
                // try to anticipate how much memory we need for collecting this <DataFile>
                try {
                    if (Size != null) {
                        int nSize = Integer.parseInt(Size);
                        
                        if (ContentType.equals(DataFile.CONTENT_EMBEDDED)) {
                            nSize += 1024; // just a little bit for whitespace & xml tags
                            m_bCollectDigest = false;
                        }
                        
                        if (ContentType.equals(DataFile.CONTENT_EMBEDDED_BASE64)) {
                            nSize *= 2;
                            m_bCollectDigest = true;
                            if (LOG.isDebugEnabled()) LOG.debug("Start collecting digest");
                        }
                        
                        if (doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) m_bCollectDigest = false;
                        
                        if (LOG.isDebugEnabled())
                            LOG.debug("Allocating buf: " + nSize + " Element: " + qName + " lname: " + lName + " uri: "
                                            + namespaceURI);

                        if (dataFileCacheOutStream == null) {// if we use temp files then we don't cache in memory 
                            m_sbCollectChars = new StringBuffer(nSize);
                        }
                    }
                } catch (Exception ex) {
                    LOG.error("Error: " + ex);
                }
            }
            
            // <SignedInfo>
            if (tag.equals("SignedInfo")) {
                if (m_nCollectMode == 0) {
                    if (doc != null
                                    && (doc.getVersion().equals(SignedDoc.VERSION_1_3)
                                                    || doc.getFormat().equals(SignedDoc.FORMAT_XADES)
                                                    || doc.getFormat().equals(SignedDoc.FORMAT_BDOC) || doc.getFormat()
                                                    .equals(SignedDoc.FORMAT_SK_XML)))
                        m_xmlnsAttr = null;
                    else
                        m_xmlnsAttr = SignedDoc.XMLNS_XMLDSIG;
                    Signature sig = getLastSignature();
                    SignedInfo si = new SignedInfo(sig);
                    sig.setSignedInfo(si);
                    String Id = attrs.getValue("Id");
                    if (Id != null) si.setId(Id);
                }
                m_nCollectMode++;
                m_sbCollectChars = new StringBuffer(1024);
            }
            
            // <SignedProperties>
            if (tag.equals("SignedProperties")) {
                String Id = attrs.getValue("Id");
                String Target = attrs.getValue("Target");
                if (m_nCollectMode == 0) {
                    try {
                        if (doc != null
                                        && (doc.getVersion().equals(SignedDoc.VERSION_1_3)
                                                        || doc.getFormat().equals(SignedDoc.FORMAT_XADES) || doc
                                                        .getFormat().equals(SignedDoc.FORMAT_BDOC)))
                            m_xmlnsAttr = null;
                        else
                            m_xmlnsAttr = SignedDoc.XMLNS_XMLDSIG;
                        Signature sig = getLastSignature();
                        SignedProperties sp = new SignedProperties(sig);
                        sp.setId(Id);
                        if (Target != null) sp.setTarget(Target);
                        sig.setSignedProperties(sp);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                m_nCollectMode++;
                m_sbCollectChars = new StringBuffer(2048);
            }
            
            // <Signature>
            if (tag.equals("Signature") && m_nCollectMode == 0) {
                if (LOG.isDebugEnabled()) LOG.debug("Start collecting <Signature>");
                if (doc == null) {
                    DigiDocException ex = new DigiDocException(DigiDocException.ERR_PARSE_XML,
                                    "Invalid signature format. Missing signed container root element.", null);
                    SAXDigiDocException.handleException(ex);
                }
                String str1 = attrs.getValue("Id");
                Signature sig = null;
                // in case of ddoc-s try find existing signature but not in case of bdoc-s.
                // to support libc++ buggy implementation with non-unique id atributes
                if (doc != null && !doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) sig = doc.findSignatureById(str1);
                if (sig == null || (sig.getId() != null && !sig.getId().equals(str1))) {
                    if (LOG.isDebugEnabled()) LOG.debug("Create signature: " + str1);
                    if (doc != null) {
                        sig = new Signature(doc);
                        try {
                            sig.setId(str1);
                        } catch (DigiDocException ex) {
                            SAXDigiDocException.handleException(ex);
                        }
                        sig.setPath(m_fileName);
                        String sProfile = doc.findSignatureProfile(m_fileName);
                        if (sProfile == null) sProfile = doc.findSignatureProfile(sig.getId());
                        if (sProfile != null) sig.setProfile(sProfile);
                        doc.addSignature(sig);
                        if (LOG.isDebugEnabled()) LOG.debug("Sig1: " + m_fileName + " profile: " + sProfile);
                    } else {
                        this.sig = new Signature(null);
                        this.sig.setPath(m_fileName);
                        String sProfile = doc.findSignatureProfile(m_fileName);
                        if (sProfile != null) this.sig.setProfile(sProfile);
                        if (LOG.isDebugEnabled()) LOG.debug("Sig2: " + m_fileName + " profile: " + sProfile);
                        sig = this.sig;
                        if (qName.startsWith("ds:")) { // only xades format uses prefix
                            try {
                                doc = new SignedDoc(SignedDoc.FORMAT_XADES, SignedDoc.VERSION_1_0);
                                doc.addSignature(sig);
                                sig.setSignedDoc(doc);
                            } catch (DigiDocException ex) {
                                SAXDigiDocException.handleException(ex);
                            }
                        }
                    }
                }
                m_sbCollectSignature = new StringBuffer();
            }
            
            // <SignatureValue>
            if (tag.equals("SignatureValue") && m_nCollectMode == 0) {
                m_strSigValTs = null;
                m_nCollectMode++;
                m_sbCollectChars = new StringBuffer(1024);
            }
            
            // <SignatureTimeStamp>
            if (tag.equals("SignatureTimeStamp") && m_nCollectMode == 0) {
                m_strSigAndRefsTs = null;
                m_nCollectMode++;
                m_sbCollectChars = new StringBuffer(2048);
            }
            
            // collect <Signature> data
            if (m_sbCollectSignature != null) {
                m_sbCollectSignature.append("<");
                m_sbCollectSignature.append(qName);

                for (int i = 0; i < attrs.getLength(); i++) {
                    m_sbCollectSignature.append(" ");
                    m_sbCollectSignature.append(attrs.getQName(i));
                    m_sbCollectSignature.append("=\"");
                    String s = attrs.getValue(i);
                    s = s.replaceAll("&", "&amp;");
                    m_sbCollectSignature.append(s);
                    m_sbCollectSignature.append("\"");
                }

                m_sbCollectSignature.append(">");
            }
            
            // if we just switched to collect-mode
            // collect SAX event data to original XML data
            // for <DataFile> we don't collect the begin and
            // end tags unless this an embedded <DataFile>
            if (m_nCollectMode > 0 || m_sbCollectChars != null) {
                StringBuffer sb = new StringBuffer();
                sb.append("<");
                sb.append(qName);

                for (int i = 0; i < attrs.getLength(); i++) {
                    if (attrs.getQName(i).equals("xmlns")) {
                        m_xmlnsAttr = null; // already have it from document
                    }

                    sb.append(" ");
                    sb.append(attrs.getQName(i));
                    sb.append("=\"");
                    
                    if (LOG.isDebugEnabled())
                        LOG.debug("Attr: " + attrs.getQName(i) + " =\'" + attrs.getValue(i) + "\'");
                    
                    if (!doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                        sb.append(ConvertUtils.escapeXmlSymbols(attrs.getValue(i)));
                    } else {
                        String sv = attrs.getValue(i);
                        if (attrs.getQName(i).equals("DigestValue") && sv.endsWith(" ")) sv = sv.replaceAll(" ", "\n");
                        sb.append(sv);
                    }
                    sb.append("\"");
                }
                
                if (m_xmlnsAttr != null) {
                    sb.append(" xmlns=\"" + m_xmlnsAttr + "\"");
                    m_xmlnsAttr = null;
                }
                
                sb.append(">");
                
                //canonicalize & calculate digest over DataFile begin-tag without content
                if (tag.equals("DataFile") && m_nCollectMode == 1) {
                    if (!doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                        
                        String strCan = sb.toString() + "</DataFile>";
                        strCan = canonicalizeXml(strCan);
                        strCan = strCan.substring(0, strCan.length() - 11);
                        
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("Canonicalized: \'" + strCan + "\'");
                        }
                        
                        try {
                            updateDigest(ConvertUtils.str2data(strCan));
                        } catch (DigiDocException e) {
                            SAXDigiDocException.handleException(e);
                        }
                    }
                } else { // we don't collect <DataFile> begin and end - tags and we don't collect if we use temp files
                    if (m_sbCollectChars != null) {
                        m_sbCollectChars.append(sb.toString());
                    }
                    
                    try {
                        if (dataFileCacheOutStream != null) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Writing dataFile to cache stream");
                            }
                            
                            dataFileCacheOutStream.write(ConvertUtils.str2data(sb.toString()));
                        }
                    } catch (IOException ex) {
                        SAXDigiDocException.handleException(ex);
                    } catch (DigiDocException e) {
                        SAXDigiDocException.handleException(e);
                    }
                }
            }
            
            // the following stuff is used also on level 1
            // because it can be part of SignedInfo or SignedProperties
            if (m_nCollectMode == 1) {
                // <CanonicalizationMethod>
                if (tag.equals("CanonicalizationMethod")) {
                    String Algorithm = attrs.getValue("Algorithm");
                    try {
                        Signature sig = getLastSignature();
                        SignedInfo si = sig.getSignedInfo();
                        si.setCanonicalizationMethod(Algorithm);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
                // <SignatureMethod>
                if (tag.equals("SignatureMethod")) {
                    String Algorithm = attrs.getValue("Algorithm");
                    try {
                        Signature sig = getLastSignature();
                        SignedInfo si = sig.getSignedInfo();
                        si.setSignatureMethod(Algorithm);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
                // <Reference>
                if (tag.equals("Reference")) {
                    String URI = attrs.getValue("URI");
                    try {
                        Signature sig = getLastSignature();
                        SignedInfo si = sig.getSignedInfo();
                        Reference ref = new Reference(si);
                        String Id = attrs.getValue("Id");
                        if (Id != null) ref.setId(Id);
                        ref.setUri(ConvertUtils.unescapeXmlSymbols(ConvertUtils.uriDecode(URI)));
                        si.addReference(ref);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
                // <Transform>
                if (tag.equals("Transform")) {
                    String Algorithm = attrs.getValue("Algorithm");
                    try {
                        if (m_tags.search("Reference") != -1) {
                            Signature sig = getLastSignature();
                            SignedInfo si = sig.getSignedInfo();
                            Reference ref = si.getLastReference();
                            ref.setTransformAlgorithm(Algorithm);
                        }
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
                // <SignatureProductionPlace>
                if (tag.equals("SignatureProductionPlace")) {
                    try {
                        Signature sig = getLastSignature();
                        SignedProperties sp = sig.getSignedProperties();
                        SignatureProductionPlace spp = new SignatureProductionPlace();
                        sp.setSignatureProductionPlace(spp);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
            }
            
            // the following is collected anyway independent of collect mode
            // <SignatureValue>
            if (tag.equals("SignatureValue")) {
                String Id = attrs.getValue("Id");
                try {
                    SignatureValue sv = new SignatureValue();
                    // VS: 2.2.24 - fix to allowe SignatureValue without Id atribute
                    if (Id != null) sv.setId(Id);
                    Signature sig = getLastSignature();
                    sig.setSignatureValue(sv);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <OCSPRef>
            if (tag.equals("OCSPRef")) {
                OcspRef orf = new OcspRef();
                Signature sig = getLastSignature();
                UnsignedProperties usp = sig.getUnsignedProperties();
                CompleteRevocationRefs rrefs = usp.getCompleteRevocationRefs();
                rrefs.addOcspRef(orf);
            }

            // <DigestMethod>
            if (tag.equals("DigestMethod")) {
                String Algorithm = attrs.getValue("Algorithm");
                try {
                    if (m_tags.search("Reference") != -1) {
                        Signature sig = getLastSignature();
                        SignedInfo si = sig.getSignedInfo();
                        Reference ref = si.getLastReference();
                        ref.setDigestAlgorithm(Algorithm);
                    } else if (m_tags.search("SigningCertificate") != -1) {
                        Signature sig = getLastSignature();
                        CertID cid = sig.getOrCreateCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                        cid.setDigestAlgorithm(Algorithm);
                    } else if (m_tags.search("CompleteCertificateRefs") != -1) {
                        Signature sig = getLastSignature();
                        CertID cid = sig.getLastCertId(); // initially set to unknown type !
                        cid.setDigestAlgorithm(Algorithm);
                    } else if (m_tags.search("CompleteRevocationRefs") != -1) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                        OcspRef orf = rrefs.getLastOcspRef();
                        if (orf != null) {
                            orf.setDigestAlgorithm(Algorithm);
                        }
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <Cert>
            if (tag.equals("Cert")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    if (m_tags.search("SigningCertificate") != -1) {
                        CertID cid = sig.getOrCreateCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                        if (id != null) cid.setId(id);
                    }
                    if (m_tags.search("CompleteCertificateRefs") != -1) {
                        CertID cid = sig.getOrCreateCertIdOfType(CertID.CERTID_TYPE_RESPONDER);
                        if (id != null) cid.setId(id);
                        sig.addCertID(cid);
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <AllDataObjectsTimeStamp>
            if (tag.equals("AllDataObjectsTimeStamp")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_ALL_DATA_OBJECTS);
                    sig.addTimestampInfo(ts);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <IndividualDataObjectsTimeStamp>
            if (tag.equals("IndividualDataObjectsTimeStamp")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS);
                    sig.addTimestampInfo(ts);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <SignatureTimeStamp>
            if (tag.equals("SignatureTimeStamp")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
                    sig.addTimestampInfo(ts);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <SigAndRefsTimeStamp>
            if (tag.equals("SigAndRefsTimeStamp")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS);
                    sig.addTimestampInfo(ts);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <RefsOnlyTimeStamp>
            if (tag.equals("RefsOnlyTimeStamp")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_REFS_ONLY);
                    sig.addTimestampInfo(ts);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <ArchiveTimeStamp>
            if (tag.equals("ArchiveTimeStamp")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = new TimestampInfo(id, TimestampInfo.TIMESTAMP_TYPE_ARCHIVE);
                    sig.addTimestampInfo(ts);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <Include>
            if (tag.equals("Include")) {
                String uri = attrs.getValue("URI");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = sig.getLastTimestampInfo();
                    IncludeInfo inc = new IncludeInfo(uri);
                    ts.addIncludeInfo(inc);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <CompleteCertificateRefs>
            if (tag.equals("CompleteCertificateRefs")) {
                String Target = attrs.getValue("Target");
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteCertificateRefs crefs = new CompleteCertificateRefs();
                up.setCompleteCertificateRefs(crefs);
                crefs.setUnsignedProperties(up);

            }
            
            // <CompleteRevocationRefs>
            if (tag.equals("CompleteRevocationRefs")) {
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteRevocationRefs rrefs = new CompleteRevocationRefs();
                up.setCompleteRevocationRefs(rrefs);
                rrefs.setUnsignedProperties(up);
            }
            
            // <OCSPIdentifier>
            if (tag.equals("OCSPIdentifier")) {
                String URI = attrs.getValue("URI");
                try {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    OcspRef orf = rrefs.getLastOcspRef();
                    orf.setUri(URI);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // the following stuff is ignored in collect mode
            // because it can only be the content of a higher element
            if (m_nCollectMode == 0) {
                // <SignedDoc>
                if (tag.equals("SignedDoc")) {
                    String format = null, version = null;
                    
                    for (int i = 0; i < attrs.getLength(); i++) {
                        String key = attrs.getQName(i);
                        
                        if (key.equals("format")) {
                            format = attrs.getValue(i);
                        }
                        
                        if (key.equals("version")) {
                            version = attrs.getValue(i);
                        }
                    }

                    try {
                        doc = new SignedDoc();
                        doc.setFormat(format);
                        doc.setVersion(version);
                        if (format != null
                                        && (format.equals(SignedDoc.FORMAT_SK_XML) || format
                                                        .equals(SignedDoc.FORMAT_DIGIDOC_XML))) {
                            doc.setProfile(SignedDoc.BDOC_PROFILE_TM); // in ddoc format we used only TM
                        }
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }

                // <KeyInfo>
                if (tag.equals("KeyInfo")) {
                    KeyInfo ki = new KeyInfo();
                    Signature sig = getLastSignature();
                    String Id = attrs.getValue("Id");
                    if (Id != null) {
                        ki.setId(Id);
                    }
                    sig.setKeyInfo(ki);
                    ki.setSignature(sig);
                }
                
                // <UnsignedProperties>
                if (tag.equals("UnsignedProperties")) {
                    String Target = attrs.getValue("Target");
                    Signature sig = getLastSignature();
                    UnsignedProperties up = new UnsignedProperties(sig);
                    sig.setUnsignedProperties(up);
                }
                
                // <EncapsulatedOCSPValue>
                if (tag.equals("EncapsulatedOCSPValue")) {
                    String Id = attrs.getValue("Id");
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    Notary not = new Notary();
                    not.setId(Id);
                    up.addNotary(not);
                    if (sig.getProfile() == null
                                    && (doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML) || doc.getFormat().equals(
                                                    SignedDoc.FORMAT_SK_XML))) {
                        sig.setProfile(SignedDoc.BDOC_PROFILE_TM);
                    }
                }
            }
        }
        
        private static final String xmlnsEtsi = "http://uri.etsi.org/01903/v1.3.2#";
        private static final String xmlnsDs = "http://www.w3.org/2000/09/xmldsig#";
        
        private byte[] addNamespaces(byte[] bCanInfo, boolean bDsNs, boolean bEtsiNs, String dsNsPref,
                        String xadesNsPref) {
            byte[] bInfo = bCanInfo;
            try {
                String s1 = new String(bCanInfo, "UTF-8"), s2 = null, s3 = null, s4 = null;
                int p1 = -1, p2 = -1, nNs = 0, nDs = -1, nEtsi = -1;
                
                p1 = s1.indexOf('>');
                if (p1 != -1) {
                    s3 = s1.substring(0, p1 + 1);
                    p2 = s1.indexOf(' ');
                    if (p2 > 0 && p2 < p1) p1 = p2;
                    s2 = s1.substring(0, p1 + 1);
                    s4 = s3.substring(p1);
                    if ((p2 = s4.indexOf("xmlns:ds")) != -1) {
                        p2 = s1.indexOf(' ', p1 + 1);
                        if (p2 > 0) p1 = p2;
                    }
                }
                if (LOG.isDebugEnabled())
                    LOG.debug("Input xml:\n------\n" + new String(bCanInfo, "UTF-8") + "\n------\n DS: " + bDsNs
                                    + " pref: " + dsNsPref + " etsi: " + bEtsiNs + " pref: " + xadesNsPref);
                if (s3 != null && s3.indexOf("xmldsig") != -1) bDsNs = false;
                if (s3 != null && s3.indexOf("etsi") != -1) bEtsiNs = false;
                if (bDsNs) nNs++;
                if (bEtsiNs) nNs++;
                if (bDsNs) {
                    if (dsNsPref == null
                                    || (dsNsPref != null && (xadesNsPref == null || (xadesNsPref != null && dsNsPref
                                                    .compareTo(xadesNsPref) < 0))))
                        nDs = 0;
                    else
                        nDs = 1;
                }
                if (bEtsiNs) {
                    if (nDs == 0)
                        nEtsi = 1;
                    else
                        nEtsi = 0;
                }
                String[] arrNs = null;
                if (nNs > 0) {
                    arrNs = new String[nNs];
                    if (LOG.isDebugEnabled())
                        LOG.debug("nDs: " + nDs + " pref: " + dsNsPref + " nns: " + nNs + " alen: " + arrNs.length);
                    if (nDs >= 0 && nDs < arrNs.length)
                        arrNs[nDs] = "xmlns" + ((dsNsPref != null) ? ":" + dsNsPref : "") + "=\"" + xmlnsDs + "\"";
                    if (nEtsi >= 0 && nEtsi < arrNs.length)
                        arrNs[nEtsi] = "xmlns" + ((xadesNsPref != null) ? ":" + xadesNsPref : "") + "=\"" + xmlnsEtsi
                                        + "\"";
                    if (LOG.isDebugEnabled())
                        LOG.debug("DS: " + bDsNs + " ns0: " + ((arrNs.length > 0) ? arrNs[0] : "NULL") + " etsi: "
                                        + bEtsiNs + " ns1: " + ((arrNs.length > 1) ? arrNs[1] : "NULL"));
                    StringBuffer sb = new StringBuffer(s1.substring(0, p1));
                    for (int i = 0; (arrNs != null) && (i < arrNs.length); i++) {
                        sb.append(" ");
                        sb.append(arrNs[i]);
                    }
                    sb.append(s1.substring(p1));
                    if (LOG.isDebugEnabled()) LOG.debug("Modified xml:\n------\n" + sb.toString() + "\n------\n");
                    bInfo = sb.toString().getBytes("UTF-8");
                }
            } catch (Exception ex) {
                LOG.error("Error adding namespaces: " + ex);
            }
            return bInfo; // deafult is to return original content
        }

        public void endElement(String namespaceURI, String sName, String qName) throws SAXException {
            if (LOG.isTraceEnabled()) {
                LOG.trace("End Element: " + qName + " collectMode: " + m_nCollectMode);
            }
            
            String tag = qName;
            
            if (tag.indexOf(':') != -1) {
                tag = qName.substring(qName.indexOf(':') + 1);
            }

            // remove last tag from stack
            m_tags.pop();
            
            // collect SAX event data to original XML data
            // for <DataFile> we don't collect the begin and
            // end tags unless this an embedded <DataFile>
            StringBuffer sb = null;
            if (m_nCollectMode > 0 && (!tag.equals("DataFile") || m_nCollectMode > 1)) {
                sb = new StringBuffer();
                sb.append("</");
                sb.append(qName);
                sb.append(">");
            }
            
            if (m_sbCollectSignature != null) {
                m_sbCollectSignature.append("</");
                m_sbCollectSignature.append(qName);
                m_sbCollectSignature.append(">");
            }
            
            // if we do cache in mem
            if (m_sbCollectChars != null && sb != null) {
                m_sbCollectChars.append(sb.toString());
            }

            // </DataFile>
            if (tag.equals("DataFile")) {
                m_nCollectMode--;
                
                if (m_nCollectMode == 0) {
                    // close DataFile cache if necessary
                    try {
                        if (dataFileCacheOutStream != null) {
                            if (sb != null) {
                                if (LOG.isTraceEnabled()) {
                                    LOG.trace("Writing into dataFile cache");
                                }
                                
                                dataFileCacheOutStream.write(ConvertUtils.str2data(sb.toString()));
                            }
                            
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("Closing datafile cache");
                            }
                            
                            dataFileCacheOutStream.close();
                            dataFileCacheOutStream = null;
                        }
                    } catch (IOException ex) {
                        SAXDigiDocException.handleException(ex);
                    } catch (DigiDocException e) {
                        SAXDigiDocException.handleException(e);
                    }
                    
                    DataFile df = doc.getLastDataFile();

                    if (df.getContentType().equals(DataFile.CONTENT_EMBEDDED)) {
                        try {
                            if (df.getDfCacheFile() == null) {
                                df.setBody(ConvertUtils.str2data(m_sbCollectChars.toString(), df.getCodepage()));
                                df.setBodyIsBase64(true);
                            }

                            // canonicalize and calculate digest of body
                            String str1 = m_sbCollectChars.toString();
                            m_sbCollectChars = null;
                            // check for whitespace before first tag of body
                            int idx1 = 0;
                            while (Character.isWhitespace(str1.charAt(idx1))) {
                                idx1++;
                            }

                            String str2 = null;
                            if (idx1 > 0) {
                                str2 = str1.substring(0, idx1);
                                updateDigest(str2.getBytes());
                                str2 = null;
                                str1 = str1.substring(idx1);
                            }
                            
                            // check for whitespace after the last xml tag of body
                            idx1 = str1.length() - 1;
                            while (Character.isWhitespace(str1.charAt(idx1))) {
                                idx1--;
                            }

                            if (idx1 < str1.length() - 1) {
                                str2 = str1.substring(idx1 + 1);
                                str1 = str1.substring(0, idx1 + 1);
                            }

                            String str3 = null;
                            if (str1.charAt(0) == '<') {
                                str3 = canonicalizeXml(str1);
                            } else {
                                str3 = str1;
                            }
                            
                            updateDigest(ConvertUtils.str2data(str3));

                            if (str2 != null) {
                                updateDigest(ConvertUtils.str2data(str2));
                                str2 = null;
                            }
                            
                            //calc digest over end tag
                            updateDigest(ConvertUtils.str2data("</DataFile>"));
                            df.setDigest(getDigest());

                            m_sbCollectChars = null; // stop collecting
                        } catch (DigiDocException ex) {
                            SAXDigiDocException.handleException(ex);
                        }
                    } else if (df.getContentType().equals(DataFile.CONTENT_EMBEDDED_BASE64)) {
                        try {
                            
                            if (doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                                String sDf = m_sbCollectChars.toString();
                                m_sbCollectChars = null;
                                byte[] bDf = Base64Util.decode(sDf);
                                updateDigest(bDf);
                                df.setDigest(getDigest());
                                if (LOG.isDebugEnabled())
                                    LOG.debug("Digest: " + df.getId() + " - " + Base64Util.encode(df.getDigest())
                                                    + " size: " + df.getSize());
                            } else {
                                long nSize = df.getSize();
                                if (df.getDfCacheFile() == null) {
                                    df.setBody(ConvertUtils.str2data(m_sbCollectChars.toString(), df.getCodepage()));
                                    df.setBodyIsBase64(true);
                                    df.setSize(nSize);
                                }
                                
                                // calc digest over end tag
                                updateDigest("</DataFile>".getBytes());
                                df.setDigest(getDigest());
                                
                                if (LOG.isDebugEnabled())
                                    LOG.debug("Digest: " + df.getId() + " - " + Base64Util.encode(df.getDigest())
                                                    + " size: " + df.getSize());
                            }

                            m_sbCollectChars = null; // stop collecting
                        } catch (DigiDocException ex) {
                            SAXDigiDocException.handleException(ex);
                        }
                    }
                    m_bCollectDigest = false;
                }
            }
            
            // </SignedInfo>
            if (tag.equals("SignedInfo")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                // calculate digest over the original
                // XML form of SignedInfo block and save it
                try {
                    Signature sig = getLastSignature();
                    SignedInfo si = sig.getSignedInfo();
                    String sSigInf = m_sbCollectChars.toString();
                    if (LOG.isDebugEnabled()) LOG.debug("SigInf:\n------\n" + sSigInf + "\n------\n");
                    //debugWriteFile("SigInfo1.xml", m_sbCollectChars.toString());
                    byte[] bCanSI = null;
                    if (doc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) {
                        bCanSI = sSigInf.getBytes();
                    } else {
                        bCanSI = canonicalizationService.canonicalize(ConvertUtils.str2data(sSigInf, "UTF-8"),
                                        SignedDoc.CANONICALIZATION_METHOD_20010315);
                    }
                    si.setOrigDigest(DDUtils.digestOfType(bCanSI,
                                    (doc.getFormat().equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                                                    : DDUtils.SHA1_DIGEST_TYPE)));
                    if (LOG.isDebugEnabled())
                        LOG.debug("SigInf:\n------\n" + new String(bCanSI) + "\n------\nHASH: "
                                        + Base64Util.encode(si.getOrigDigest()));
                    if (doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                        boolean bEtsiNs = false;
                        if (m_nsXadesPref != null && m_nsXadesPref.length() > 0) bEtsiNs = true;
                        bCanSI = addNamespaces(bCanSI, true, bEtsiNs, m_nsDsPref, m_nsXadesPref);
                        String sDigType = DDUtils.sigMeth2Type(si.getSignatureMethod());
                        if (sDigType != null)
                            si.setOrigDigest(DDUtils.digestOfType(bCanSI, sDigType));
                        else
                            throw new DigiDocException(DigiDocException.ERR_SIGNATURE_METHOD,
                                            "Invalid signature method: " + si.getSignatureMethod(), null);
                        if (LOG.isDebugEnabled()) LOG.debug("\nHASH: " + Base64Util.encode(si.getOrigDigest()));
                    }
                    m_sbCollectChars = null; // stop collecting
                    //debugWriteFile("SigInfo2.xml", si.toString());
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }

            }
            
            // </SignedProperties>
            if (tag.equals("SignedProperties")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                // calculate digest over the original
                // XML form of SignedInfo block and save it
                try {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    String sigProp = m_sbCollectChars.toString();
                    byte[] bSigProp = ConvertUtils.str2data(sigProp, "UTF-8");
                    byte[] bDig0 = DDUtils.digestOfType(bSigProp, DDUtils.SHA1_DIGEST_TYPE);

                    if (LOG.isDebugEnabled())
                        LOG.debug("SigProp0:\n------\n" + sigProp + "\n------" + " len: " + sigProp.length()
                                        + " sha1 HASH0: " + Base64Util.encode(bDig0));

                    byte[] bCanProp = canonicalizationService.canonicalize(bSigProp,
                                    SignedDoc.CANONICALIZATION_METHOD_20010315);
                    
                    if (LOG.isDebugEnabled())
                        LOG.debug("SigProp1:\n------\n" + new String(bCanProp, "UTF-8") + "\n------" + " len: "
                                        + bCanProp.length);
                    
                    if (doc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                        boolean bNeedDsNs = false;
                        String st1 = new String(bCanProp);
                        if (st1.indexOf("<ds:X509IssuerName>") != -1) {
                            bNeedDsNs = true;
                        }
                        bCanProp = addNamespaces(bCanProp, bNeedDsNs, true, m_nsDsPref, m_nsXadesPref);
                        Reference spRef = sig.getSignedInfo().getReferenceForSignedProperties(sp);
                        String sDigType = DDUtils.digAlg2Type(spRef.getDigestAlgorithm());
                        sp.setOrigDigest(DDUtils.digestOfType(bCanProp, sDigType));
                        if (LOG.isDebugEnabled()) LOG.debug("\nHASH: " + Base64Util.encode(sp.getOrigDigest()));
                    }

                    m_sbCollectChars = null; // stop collecting
                    CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                    if (cid != null) {
                        if (cid.getId() != null)
                            sp.setCertId(cid.getId());
                        else if (!sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3)
                                        && !doc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                            sp.setCertId(sig.getId() + "-CERTINFO");
                        sp.setCertSerial(cid.getSerial());
                        sp.setCertDigestAlgorithm(cid.getDigestAlgorithm());
                        if (cid.getDigestValue() != null) {
                            sp.setCertDigestValue(cid.getDigestValue());
                        }
                    }
                    
                    String sDigType1 = DDUtils.digAlg2Type(sp.getCertDigestAlgorithm());
                    sp.setOrigDigest(DDUtils.digestOfType(bCanProp, sDigType1));
                    if (LOG.isDebugEnabled())
                        LOG.debug("SigProp2:\n------\n" + new String(bCanProp) + "\n------\n" + " len: "
                                        + bCanProp.length + " digtype: " + sDigType1 + " HASH: "
                                        + Base64Util.encode(sp.getOrigDigest()));
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                } catch (UnsupportedEncodingException e) {
                    SAXDigiDocException.handleException(e);
                }
            }
            
            // </SignatureValue>
            if (tag.equals("SignatureValue")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                m_strSigValTs = m_sbCollectChars.toString();
                m_sbCollectChars = null; // stop collecting             
            }
            
            // </CompleteRevocationRefs>
            if (tag.equals("CompleteRevocationRefs")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                if (m_sbCollectChars != null) m_strSigAndRefsTs = m_strSigValTs + m_sbCollectChars.toString();
                m_sbCollectChars = null; // stop collecting         
            }
            
            // </Signature>
            if (tag.equals("Signature")) {
                if (m_nCollectMode == 0) {
                    if (LOG.isTraceEnabled()) LOG.trace("End collecting <Signature>");
                    try {
                        Signature sig = getLastSignature();
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("Set sig content:\n---\n" + m_sbCollectSignature.toString() + "\n---\n");
                        }
                        if (m_sbCollectSignature != null) {
                            sig.setOrigContent(ConvertUtils.str2data(m_sbCollectSignature.toString(), "UTF-8"));
                            if (LOG.isTraceEnabled())
                                LOG.trace("SIG orig content set: " + sig.getId() + " len: "
                                                + ((sig.getOrigContent() == null) ? 0 : sig.getOrigContent().length));
                            //debugWriteFile("SIG-" + sig.getId() + ".txt", m_sbCollectSignature.toString()); 
                            m_sbCollectSignature = null; // reset collecting
                        }
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
            }
            
            // </SignatureTimeStamp>
            if (tag.equals("SignatureTimeStamp")) {
                if (LOG.isTraceEnabled()) LOG.trace("End collecting <SignatureTimeStamp>");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
                    if (ts != null && m_strSigValTs != null) {
                        byte[] bCanXml = canonicalizationService.canonicalize(
                                        ConvertUtils.str2data(m_strSigValTs, "UTF-8"),
                                        SignedDoc.CANONICALIZATION_METHOD_20010315);
                        byte[] hash = DDUtils.digest(bCanXml);
                        if (LOG.isDebugEnabled())
                            LOG.debug("SigValTS \n---\n" + new String(bCanXml) + "\n---\nHASH: "
                                            + Base64Util.encode(hash));
                        ts.setHash(hash);
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </SigAndRefsTimeStamp>
            if (tag.equals("SigAndRefsTimeStamp")) {
                if (LOG.isTraceEnabled()) LOG.trace("End collecting <SigAndRefsTimeStamp>");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS);
                    if (ts != null && m_strSigAndRefsTs != null) {
                        String canXml = "<a>" + m_strSigAndRefsTs + "</a>";
                        byte[] bCanXml = canonicalizationService.canonicalize(ConvertUtils.str2data(canXml, "UTF-8"),
                                        SignedDoc.CANONICALIZATION_METHOD_20010315);
                        canXml = new String(bCanXml, "UTF-8");
                        canXml = canXml.substring(3, canXml.length() - 4);
                        byte[] hash = DDUtils.digest(ConvertUtils.str2data(canXml, "UTF-8"));
                        if (LOG.isDebugEnabled())
                            LOG.debug("SigAndRefsTimeStamp \n---\n" + canXml + "\n---\n" + Base64Util.encode(hash));
                        ts.setHash(hash);
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                } catch (UnsupportedEncodingException e) {
                    SAXDigiDocException.handleException(e);
                }
            }
            
            // the following stuff is used also in
            // collect mode level 1 because it can be part 
            // of SignedInfo or SignedProperties
            if (m_nCollectMode == 1) {
                // </SigningTime>
                if (tag.equals("SigningTime")) {
                    try {
                        Signature sig = getLastSignature();
                        SignedProperties sp = sig.getSignedProperties();
                        sp.setSigningTime(ConvertUtils.string2date(m_sbCollectItem.toString(), doc));
                        m_sbCollectItem = null; // stop collecting
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                // </ClaimedRole>
                if (tag.equals("ClaimedRole")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    sp.addClaimedRole(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </City>
                if (tag.equals("City")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setCity(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </StateOrProvince>
                if (tag.equals("StateOrProvince")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setStateOrProvince(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </CountryName>
                if (tag.equals("CountryName")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setCountryName(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </PostalCode>
                if (tag.equals("PostalCode")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setPostalCode(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }

            } // level 1  
            
            // the following is collected on any level
            // </DigestValue>
            if (tag.equals("DigestValue")) {
                try {
                    if (m_tags.search("Reference") != -1) {
                        Signature sig = getLastSignature();
                        SignedInfo si = sig.getSignedInfo();
                        Reference ref = si.getLastReference();
                        ref.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        m_sbCollectItem = null; // stop collecting
                    } else if (m_tags.search("SigningCertificate") != -1) {
                        Signature sig = getLastSignature();
                        SignedProperties sp = sig.getSignedProperties();
                        sp.setCertDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                        if (cid != null) cid.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        m_sbCollectItem = null; // stop collecting
                    } else if (m_tags.search("CompleteCertificateRefs") != -1) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteCertificateRefs crefs = up.getCompleteCertificateRefs();
                        CertID cid = crefs.getLastCertId();
                        if (cid != null) cid.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        if (LOG.isDebugEnabled())
                            LOG.debug("CertID: " + cid.getId() + " digest: " + m_sbCollectItem.toString());
                        m_sbCollectItem = null; // stop collecting
                    } else if (m_tags.search("CompleteRevocationRefs") != -1) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                        OcspRef orf = rrefs.getLastOcspRef();
                        orf.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        if (LOG.isDebugEnabled()) LOG.debug("Revoc ref: " + m_sbCollectItem.toString());
                        m_sbCollectItem = null; // stop collecting
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </IssuerSerial>
            if (tag.equals("IssuerSerial") && doc != null && !doc.getVersion().equals(SignedDoc.VERSION_1_3)
                            && !doc.getFormat().equals(SignedDoc.FORMAT_BDOC)
                            && !doc.getFormat().equals(SignedDoc.FORMAT_XADES)) {
                try {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getLastCertId();
                    if (LOG.isDebugEnabled()) LOG.debug("X509SerialNumber 0: " + m_sbCollectItem.toString());
                    if (cid != null) cid.setSerial(ConvertUtils.string2bigint(m_sbCollectItem.toString()));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </X509SerialNumber>
            if (tag.equals("X509SerialNumber")
                            && doc != null
                            && (doc.getVersion().equals(SignedDoc.VERSION_1_3)
                                            || doc.getFormat().equals(SignedDoc.FORMAT_BDOC) || doc.getFormat().equals(
                                            SignedDoc.FORMAT_XADES))) {
                try {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getLastCertId();
                    if (LOG.isDebugEnabled()) LOG.debug("X509SerialNumber: " + m_sbCollectItem.toString());
                    if (cid != null) cid.setSerial(ConvertUtils.string2bigint(m_sbCollectItem.toString()));
                    if (LOG.isDebugEnabled())
                        LOG.debug("X509SerialNumber: " + cid.getSerial() + " type: " + cid.getType());
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </X509IssuerName>
            if (tag.equals("X509IssuerName")
                            && doc != null
                            && (doc.getVersion().equals(SignedDoc.VERSION_1_3)
                                            || doc.getFormat().equals(SignedDoc.FORMAT_BDOC) || doc.getFormat().equals(
                                            SignedDoc.FORMAT_XADES))) {
                try {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getLastCertId();
                    String s = m_sbCollectItem.toString();
                    if (cid != null) cid.setIssuer(s);
                    if (LOG.isDebugEnabled())
                        LOG.debug("X509IssuerName: " + s + " type: " + cid.getType() + " nr: " + cid.getSerial());
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            //</EncapsulatedTimeStamp>
            if (tag.equals("EncapsulatedTimeStamp")) {
                Signature sig = getLastSignature();
                TimestampInfo ts = sig.getLastTimestampInfo();
                try {
                    ts.setTimeStampToken(((BouncyCastleTimestampService) timestampService).readTsTok(Base64Util
                                    .decode(m_sbCollectItem.toString())));
                    if (LOG.isDebugEnabled())
                        LOG.debug("TS: " + ts.getId() + " type: " + ts.getType() + " time: " + ts.getTime()
                                        + " digest: " + Base64Util.encode(ts.getMessageImprint()));
                } catch (Exception ex) {
                    SAXDigiDocException.handleException(new DigiDocException(DigiDocException.ERR_TIMESTAMP_RESP,
                                    "Invalid timestamp token", ex));
                }
                m_sbCollectItem = null; // stop collecting
            }
            
            // </ResponderID>
            if (tag.equals("ResponderID")) {
                try {
                    if (!doc.getFormat().equals(SignedDoc.FORMAT_BDOC)
                                    && !doc.getFormat().equals(SignedDoc.FORMAT_XADES)) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                        if (LOG.isDebugEnabled()) LOG.debug("ResponderID: " + m_sbCollectItem.toString());
                        OcspRef orf = rrefs.getLastOcspRef();
                        orf.setResponderId(m_sbCollectItem.toString());
                        m_sbCollectItem = null; // stop collecting
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </ByName>
            if (tag.equals("ByName")) {
                try {
                    if (doc.getFormat().equals(SignedDoc.FORMAT_BDOC) || doc.getFormat().equals(SignedDoc.FORMAT_XADES)) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                        if (LOG.isDebugEnabled()) LOG.debug("ResponderID by-name: " + m_sbCollectItem.toString());
                        OcspRef orf = rrefs.getLastOcspRef();
                        orf.setResponderId(m_sbCollectItem.toString());
                        m_sbCollectItem = null; // stop collecting
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }

            // </ProducedAt>
            if (tag.equals("ProducedAt")) {
                try {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    OcspRef orf = rrefs.getLastOcspRef();
                    orf.setProducedAt(ConvertUtils.string2date(m_sbCollectItem.toString(), doc));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // the following stuff is ignored in collect mode
            // because it can only be the content of a higher element
            // </SignatureValue>
            if (tag.equals("SignatureValue")) {
                try {
                    Signature sig = getLastSignature();
                    SignatureValue sv = sig.getSignatureValue();
                    sv.setValue(Base64Util.decode(m_sbCollectItem.toString().trim()));
                    if (LOG.isDebugEnabled())
                        LOG.debug("SIGVAL mode: " + m_nCollectMode + ":\n--\n"
                                        + (m_sbCollectItem != null ? m_sbCollectItem.toString() : "NULL")
                                        + "\n---\n len: " + ((sv.getValue() != null) ? sv.getValue().length : 0));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </X509Certificate>
            if (tag.equals("X509Certificate")) {
                try {
                    Signature sig = getLastSignature();
                    CertValue cval = sig.getLastCertValue();
                    cval.setCert(DDUtils.readCertificate(Base64Util.decode(m_sbCollectItem.toString())));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </EncapsulatedX509Certificate>
            if (tag.equals("EncapsulatedX509Certificate")) {
                try {
                    Signature sig = getLastSignature();
                    CertValue cval = sig.getLastCertValue();
                    cval.setCert(DDUtils.readCertificate(Base64Util.decode(m_sbCollectItem.toString())));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </EncapsulatedOCSPValue>
            if (tag.equals("EncapsulatedOCSPValue")) {
                try {
                    Signature sig = getLastSignature();
                    // first we have to find correct certid and certvalue types
                    findCertIDandCertValueTypes(sig);
                    UnsignedProperties up = sig.getUnsignedProperties();
                    Notary not = up.getLastNotary();
                    not.setOcspResponseData(Base64Util.decode(m_sbCollectItem.toString()));
                    notaryService.parseAndVerifyResponse(sig, not);
                    // in 1.1 we had bad OCPS digest
                    if (doc != null && doc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)
                                    && doc.getVersion().equals(SignedDoc.VERSION_1_1)) {
                        CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                        OcspRef orf = rrefs.getLastOcspRef();
                        orf.setDigestValue(DDUtils.digestOfType(not.getOcspResponseData(),
                                        (doc.getFormat().equals(SignedDoc.FORMAT_BDOC) ? DDUtils.SHA256_DIGEST_TYPE
                                                        : DDUtils.SHA1_DIGEST_TYPE)));
                    }
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
        }

        public void characters(char buf[], int offset, int len) throws SAXException {
            String s = new String(buf, offset, len);
            // just collect the data since it could
            // be on many lines and be processed in many events

            if (LOG.isTraceEnabled()) {
                LOG.trace("chars collectChars:" + (m_sbCollectChars != null) + " collectItem:"
                                + (m_sbCollectItem != null) + " '" + s.replace("\n", "\\n") + "'");
            }
            if (s != null) {
                if (m_sbCollectItem != null) {
                    m_sbCollectItem.append(s);
                }
                
                if (m_sbCollectChars != null) {
                    m_sbCollectChars.append(ConvertUtils.escapeTextNode(s));
                }
                
                if (m_sbCollectSignature != null) {
                    m_sbCollectSignature.append(ConvertUtils.escapeXmlSymbols(s));
                }
                
                if (m_digest != null && m_bCollectDigest) {
                    updateDigest(s.getBytes());
                }
                
                try {
                    if (dataFileCacheOutStream != null) {
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("Writing dataFile to cache stream");
                        }
                        
                        dataFileCacheOutStream.write(ConvertUtils.str2data(s));
                    }
                } catch (IOException ex) {
                    SAXDigiDocException.handleException(ex);
                } catch (DigiDocException e) {
                    SAXDigiDocException.handleException(e);
                }
            }
        }

        public Signature getLastSignature() {
            if (doc != null) {
                return doc.getLastSignature();
            } else {
                return sig;
            }
        }

        private void updateDigest(byte[] data) {
            if (m_digest == null) {
                try {
                    m_digest = MessageDigest.getInstance("SHA-1");
                } catch (NoSuchAlgorithmException e) {
                    LOG.error("Error calculating digest: " + e);
                }
            }
            m_digest.update(data);
        }
        
        private void findCertIDandCertValueTypes(Signature sig) {
            if (LOG.isTraceEnabled()) LOG.trace("Sig: " + sig.getId() + " certids: " + sig.countCertIDs());
            for (int i = 0; (sig != null) && (i < sig.countCertIDs()); i++) {
                CertID cid = sig.getCertID(i);
                if (LOG.isTraceEnabled())
                    LOG.trace("CertId: " + cid.getId() + " type: " + cid.getType() + " nr: " + cid.getSerial());
                if (cid.getType() == CertID.CERTID_TYPE_UNKNOWN) {
                    CertValue cval = sig.findCertValueWithSerial(cid.getSerial());
                    if (cval != null) {
                        String cn = null;
                        try {
                            cn = DDUtils.getCommonName(cval.getCert().getSubjectDN().getName());
                            if (LOG.isTraceEnabled())
                                LOG.trace("CertId type: " + cid.getType() + " nr: " + cid.getSerial() + " cval: "
                                                + cval.getId() + " CN: " + cn);
                            if (notaryService.isKnownOCSPCert(cn)) {
                                if (LOG.isInfoEnabled()) LOG.trace("Cert: " + cn + " is OCSP responders cert");
                                cid.setType(CertID.CERTID_TYPE_RESPONDER);
                                cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                            }
                            if (ConvertUtils.isKnownTSACert(cn)) {
                                if (LOG.isTraceEnabled()) LOG.trace("Cert: " + cn + " is TSA cert");
                                cid.setType(CertID.CERTID_TYPE_TSA);
                                cval.setType(CertValue.CERTVAL_TYPE_TSA);
                                if (LOG.isTraceEnabled())
                                    LOG.trace("CertId: " + cid.getId() + " type: " + cid.getType() + " nr: "
                                                    + cid.getSerial());
                            }
                        } catch (DigiDocException ex) {
                            LOG.error("Error setting type on certid or certval: " + cn);
                        }
                    }
                }
                
            } // for i < sig.countCertIDs()
            if (LOG.isTraceEnabled()) LOG.trace("Sig: " + sig.getId() + " certvals: " + sig.countCertValues());
            for (int i = 0; (sig != null) && (i < sig.countCertValues()); i++) {
                CertValue cval = sig.getCertValue(i);
                if (LOG.isTraceEnabled()) LOG.trace("CertValue: " + cval.getId() + " type: " + cval.getType());
                if (cval.getType() == CertValue.CERTVAL_TYPE_UNKNOWN) {
                    String cn = null;
                    try {
                        cn = DDUtils.getCommonName(cval.getCert().getSubjectDN().getName());
                        if (notaryService.isKnownOCSPCert(cn)) {
                            if (LOG.isTraceEnabled()) LOG.trace("Cert: " + cn + " is OCSP responders cert");
                            cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                        }
                        if (ConvertUtils.isKnownTSACert(cn)) {
                            if (LOG.isTraceEnabled()) LOG.trace("Cert: " + cn + " is TSA cert");
                            cval.setType(CertValue.CERTVAL_TYPE_TSA);
                        }
                    } catch (DigiDocException ex) {
                        LOG.error("Error setting type on certid or certval: " + cn);
                    }
                }
            }
        }

        /**
         * Helper method to calculate the digest result and
         * reset digest
         * 
         * @return sha-1 digest value
         */
        private byte[] getDigest() {
            byte[] digest = null;
            // if not inited yet then initialize digest
            digest = m_digest.digest();
            m_digest = null; // reset for next calculation
            return digest;
        }

        /**
         * Helper method to canonicalize a piece of xml
         * 
         * @param xml data to be canonicalized
         * @return canonicalized xml
         */
        private String canonicalizeXml(String xml) {
            try {
                return new String(canonicalizationService.canonicalize(xml.getBytes("UTF-8"),
                                SignedDoc.CANONICALIZATION_METHOD_20010315), "UTF-8");
            } catch (Exception e) {
                LOG.error("Canonicalizing exception: " + e);
            }
            return null;
        }
    }
}
