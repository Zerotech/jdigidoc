package ee.sk.digidoc.services;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Stack;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
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
    
    public SAXDigidocServiceImpl(
            CanonicalizationService canonicalizationService,
            NotaryService notaryService) {
        this.canonicalizationService = canonicalizationService;
        this.notaryService = notaryService;
    }
    
    public SignedDoc readSignedDoc(InputStream digiDocStream) throws DigiDocException {
        DDHandler handler = new DDHandler();
        SAXParserFactory factory = SAXParserFactory.newInstance();
        try {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(digiDocStream, handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        
        if (handler.getSignedDoc() == null) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "This document is not in digidoc format", null);
        }
            
        return handler.getSignedDoc();
    }

    public SignedDoc readSignedDoc(String fileName) throws DigiDocException {
        DDHandler handler = new DDHandler();
        SAXParserFactory factory = SAXParserFactory.newInstance();

        try {
            SAXParser saxParser = factory.newSAXParser();
            FileInputStream is = new FileInputStream(fileName);
            saxParser.parse(is, handler);
            is.close();
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        
        if (handler.getSignedDoc() == null) {
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,"This document is not in digidoc format", null);
        }
            
        return handler.getSignedDoc();
    }
    
    
    class DDHandler extends DefaultHandler {
        private Stack<String> m_tags = new Stack<String>();
        private SignedDoc doc;
        private String m_strSigValTs, m_strSigAndRefsTs;
        private StringBuffer m_sbCollectChars;
        private StringBuffer m_sbCollectItem;
        private StringBuffer m_sbCollectSignature;
        private boolean m_bCollectDigest;
        private String m_xmlnsAttr;
        
        /** This mode means collect SAX events into xml data
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
        
        
        public void startDocument() throws SAXException {
            if (LOG.isTraceEnabled()) {
                LOG.trace("startDocument");
            }
            
            m_nCollectMode = 0;
            m_xmlnsAttr = null;
            dataFileCacheOutStream = null;
        }
        
        public void endDocument() throws SAXException {
            if (LOG.isTraceEnabled()) {
                LOG.trace("endDocument");
            }
        }
        
        public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
                throws SAXDigiDocException {

            if (LOG.isTraceEnabled()) {
                LOG.trace("Start Element: " + qName + " lname: " + lName + " uri: " + namespaceURI);
            }
            
            m_tags.push(qName);
            
            if (qName.equals("SigningTime") ||
               qName.equals("IssuerSerial") ||
               qName.equals("X509SerialNumber") ||
               qName.equals("X509IssuerName") ||
               qName.equals("ClaimedRole") ||
               qName.equals("City") ||
               qName.equals("StateOrProvince") ||
               qName.equals("CountryName") ||
               qName.equals("PostalCode") ||
               qName.equals("SignatureValue") ||
               qName.equals("DigestValue") ||
               //qName.equals("EncapsulatedX509Certificate") ||
               qName.equals("IssuerSerial") ||
               qName.equals("ResponderID") ||
               qName.equals("X509SerialNumber") ||
               qName.equals("ProducedAt") ||
               qName.equals("EncapsulatedTimeStamp") ||
               qName.equals("EncapsulatedOCSPValue") ) {
                m_sbCollectItem = new StringBuffer();
            }

            // <X509Certificate>
            // Prepare CertValue object
            if (qName.equals("X509Certificate")) {
                Signature sig = getLastSignature();
                CertValue cval = null; 
                try {
                    if (LOG.isTraceEnabled())
                        LOG.trace("Adding signers cert to: " + sig.getId());
                    cval = sig.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
                } catch(DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
                m_sbCollectItem = new StringBuffer();
            }
            
            // <EncapsulatedX509Certificate>
            // Prepare CertValue object and record it's id
            if (qName.equals("EncapsulatedX509Certificate")) {
                Signature sig = getLastSignature();
                String id = null;
                for (int i = 0; i < attrs.getLength(); i++) {
                    String key = attrs.getQName(i);
                    if (key.equals("Id")) {
                        id = attrs.getValue(i);
                    }
                }
                CertValue cval = new CertValue();
                if (id != null) {
                    cval.setId(id);
                    try {
                      if (id.indexOf("RESPONDER_CERT") != -1)
                        cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                    } catch(DigiDocException ex) {
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
            if (qName.equals("DataFile")) {
                String ContentType = null, Filename = null, Id = null, MimeType = null, Size = null, DigestType = null, Codepage = null;
                byte[] DigestValue = null;
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
                            df.setDigestValue(DigestValue);
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
                                LOG.trace("Datafile cache enabled, Id: " + Id 
                                        + " size: " + df.getSize() 
                                        + " cache-file: " + fCache.getAbsolutePath());
                            }
                            
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
                        }

                        if (dataFileCacheOutStream == null) {// if we use temp files then we don't cache in memory 
                            m_sbCollectChars = new StringBuffer(nSize);
                        }
                    }                   
                } catch(Exception ex) {
                    LOG.error("Error: " + ex);
                }
            }
            
            // <SignedInfo>
            if (qName.equals("SignedInfo")) {
                if (m_nCollectMode == 0) {
                    if (doc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                        doc.getVersion().equals(SignedDoc.VERSION_1_4))
                        m_xmlnsAttr = null;
                    else
                        m_xmlnsAttr = SignedDoc.XMLNS_XMLDSIG;
                    Signature sig = getLastSignature();
                    SignedInfo si = new SignedInfo(sig);
                    sig.setSignedInfo(si);
                }
                m_nCollectMode++;
                m_sbCollectChars = new StringBuffer(1024);
            }
            
            // <SignedProperties>
            if (qName.equals("SignedProperties")) {
                String Id = attrs.getValue("Id");
                String Target = attrs.getValue("Target");
                if (m_nCollectMode == 0) {
                    try {
                        if (doc.getVersion().equals(SignedDoc.VERSION_1_3) ||
                            doc.getVersion().equals(SignedDoc.VERSION_1_4))
                            m_xmlnsAttr = null;
                        else
                            m_xmlnsAttr = SignedDoc.XMLNS_XMLDSIG;
                        Signature sig = getLastSignature();
                        SignedProperties sp = new SignedProperties(sig);
                        sp.setId(Id);
                        if (Target != null)
                            sp.setTarget(Target);
                        sig.setSignedProperties(sp);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                m_nCollectMode++;
                m_sbCollectChars = new StringBuffer(2048);
            }
            
            // <Signature>
            if (qName.equals("Signature") && m_nCollectMode == 0) {
                if (LOG.isTraceEnabled())
                    LOG.trace("Start collecting <Signature>");
                String str1 = attrs.getValue("Id");
                Signature sig = getLastSignature();
                if (sig == null || !sig.getId().equals(str1)) {
                    if (LOG.isTraceEnabled())
                        LOG.trace("Create signature: " + str1);
                    sig = new Signature(doc);
                    doc.addSignature(sig);
                }
                try {
                  if (str1 != null)
                    sig.setId(str1);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
                m_sbCollectSignature = new StringBuffer();
            }
            
            // <SignatureValue>
            if (qName.equals("SignatureValue") && m_nCollectMode == 0) {
                m_strSigValTs = null; 
                m_nCollectMode++;
                m_sbCollectChars = new StringBuffer(1024);
            }
            
            // <SignatureTimeStamp>
            if (qName.equals("SignatureTimeStamp") && m_nCollectMode == 0) {
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
                    m_sbCollectSignature.append(attrs.getValue(i));
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
                    sb.append(attrs.getValue(i));
                    sb.append("\"");
                }
                
                if (m_xmlnsAttr != null) {
                    sb.append(" xmlns=\"" + m_xmlnsAttr + "\"");
                    m_xmlnsAttr = null;
                }
                
                sb.append(">"); 
                
                //canonicalize & calculate digest over DataFile begin-tag without content
                if (qName.equals("DataFile") && m_nCollectMode == 1) {
                    String strCan = sb.toString() + "</DataFile>";
                    strCan = canonicalizeXml(strCan);
                    strCan = strCan.substring(0, strCan.length() - 11);
                    
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Canonicalized: \'" + strCan + "\'");
                    }
                    
                    updateDigest(ConvertUtils.str2data(strCan));                    
                } else { // we don't collect <DataFile> begin and end - tags and we don't collect if we use temp files
                    if (m_sbCollectChars != null) {
                        m_sbCollectChars.append(sb.toString());
                    }
                    
                    try {
                        if (dataFileCacheOutStream != null) {
                            if (LOG.isTraceEnabled()) {
                                LOG.trace("Writing dataFile to cache stream");
                            }

                            dataFileCacheOutStream.write(ConvertUtils.str2data(sb.toString()));
                        }
                    } catch (IOException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
            }
            
            // the following stuff is used also on level 1
            // because it can be part of SignedInfo or SignedProperties
            if (m_nCollectMode == 1)  {
                // <CanonicalizationMethod>
                if (qName.equals("CanonicalizationMethod")) {
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
                if (qName.equals("SignatureMethod")) {
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
                if (qName.equals("Reference")) {
                    String URI = attrs.getValue("URI");
                    try {
                        Signature sig = getLastSignature();
                        SignedInfo si = sig.getSignedInfo();
                        Reference ref = new Reference(si);
                        ref.setUri(URI);
                        si.addReference(ref);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
                // <Transform>
                if (qName.equals("Transform")) {
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
                if (qName.equals("SignatureProductionPlace")) {
                    try {
                        Signature sig = getLastSignature();
                        SignedProperties sp = sig.getSignedProperties();
                        SignatureProductionPlace spp =
                            new SignatureProductionPlace();
                        sp.setSignatureProductionPlace(spp);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
            }
            
            // the following is collected anyway independent of collect mode
            // <SignatureValue>
            if (qName.equals("SignatureValue")) {
                String Id = attrs.getValue("Id");
                try {
                    SignatureValue sv = new SignatureValue();
                    // VS: 2.2.24 - fix to allowe SignatureValue without Id atribute
                    if (Id != null)
                        sv.setId(Id);
                    Signature sig = getLastSignature();
                    sig.setSignatureValue(sv);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <DigestMethod>
            if (qName.equals("DigestMethod")) {
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
                    } else if (
                        m_tags.search("CompleteCertificateRefs") != -1) {
                        Signature sig = getLastSignature();
                        CertID cid = sig.getLastCertId(); // initially set to unknown type !
                        cid.setDigestAlgorithm(Algorithm);
                    } else if (m_tags.search("CompleteRevocationRefs") != -1) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                        rrefs.setDigestAlgorithm(Algorithm);
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <Cert>
            if (qName.equals("Cert")) {
                String id = attrs.getValue("Id");
                try {
                    Signature sig = getLastSignature();
                    if (m_tags.search("SigningCertificate") != -1) {
                        CertID cid = sig.getOrCreateCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                        if (id != null)
                            cid.setId(id);
                    }
                    if (m_tags.search("CompleteCertificateRefs") != -1) {
                        CertID cid = new CertID();                          
                        if (id != null)
                            cid.setId(id);
                        sig.addCertID(cid);
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // <AllDataObjectsTimeStamp>
            if (qName.equals("AllDataObjectsTimeStamp")) {
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
            if (qName.equals("IndividualDataObjectsTimeStamp")) {
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
            if (qName.equals("SignatureTimeStamp")) {
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
            if (qName.equals("SigAndRefsTimeStamp")) {
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
            if (qName.equals("RefsOnlyTimeStamp")) {
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
            if (qName.equals("ArchiveTimeStamp")) {
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
            if (qName.equals("Include")) {
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
            if (qName.equals("CompleteCertificateRefs")) {
                String Target = attrs.getValue("Target");
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteCertificateRefs crefs = new CompleteCertificateRefs();
                up.setCompleteCertificateRefs(crefs);
                crefs.setUnsignedProperties(up);

            }
            
            // <CompleteRevocationRefs>
            if (qName.equals("CompleteRevocationRefs")) {
                Signature sig = getLastSignature();
                UnsignedProperties up = sig.getUnsignedProperties();
                CompleteRevocationRefs rrefs = new CompleteRevocationRefs();
                up.setCompleteRevocationRefs(rrefs);
                rrefs.setUnsignedProperties(up);
            }
            
            // <OCSPIdentifier>
            if (qName.equals("OCSPIdentifier")) {
                String URI = attrs.getValue("URI");
                try {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    rrefs.setUri(URI);
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // the following stuff is ignored in collect mode
            // because it can only be the content of a higher element
            if (m_nCollectMode == 0) {
                // <SignedDoc>
                if (qName.equals("SignedDoc")) {
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
                        doc = new SignedDoc(format, version);
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }

                // <KeyInfo>
                if (qName.equals("KeyInfo")) {
                    KeyInfo ki = new KeyInfo();
                    Signature sig = getLastSignature();
                    sig.setKeyInfo(ki);
                    ki.setSignature(sig);
                }
                
                // <UnsignedProperties>
                if (qName.equals("UnsignedProperties")) {
                    String Target = attrs.getValue("Target");
                    Signature sig = getLastSignature();
                    UnsignedProperties up = new UnsignedProperties(sig);
                    sig.setUnsignedProperties(up);
                }
                
                // <EncapsulatedOCSPValue>
                if (qName.equals("EncapsulatedOCSPValue")) {
                    String Id = attrs.getValue("Id");
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    Notary not = new Notary();
                    not.setId(Id);
                    up.setNotary(not);
                }
            } // if (m_nCollectMode == 0)
        }

        public void endElement(String namespaceURI, String sName, String qName) throws SAXException {
            if (LOG.isTraceEnabled()) {
                LOG.trace("End Element: " + qName + " collectMode: " + m_nCollectMode);
            }

            // remove last tag from stack
            m_tags.pop();
            
            // collect SAX event data to original XML data
            // for <DataFile> we don't collect the begin and
            // end tags unless this an embedded <DataFile>
            StringBuffer sb = null;
            if (m_nCollectMode > 0 && (!qName.equals("DataFile") || m_nCollectMode > 1)) {
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
            if (qName.equals("DataFile")) {
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
                    }
                    
                    DataFile df = doc.getLastDataFile();
 
                    if (df.getContentType().equals(DataFile.CONTENT_EMBEDDED)) {
                        try {
                            if (df.getDfCacheFile() == null) { 
                                df.setBody(ConvertUtils.str2data(sb.toString(), df.getCodepage()));
                            }

                            // canonicalize and calculate digest of body
                            String str1 = sb.toString();
                            m_sbCollectChars = null;
                            // check for whitespace before first tag of body
                            int idx1 = 0;
                            while(Character.isWhitespace(str1.charAt(idx1))) {
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
                            idx1 = str1.length()-1;
                            while(Character.isWhitespace(str1.charAt(idx1))) {
                                idx1--;
                            }

                            if (idx1 < str1.length() - 1) {
                                str2 = str1.substring(idx1+1);
                                str1 = str1.substring(0, idx1+1);
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
                            // calc digest over end tag
                            updateDigest("</DataFile>".getBytes());
                            df.setDigest(getDigest());

                            if (df.getDfCacheFile() == null) {
                                if (sb != null) {
                                    df.setBody(ConvertUtils.str2data(sb.toString(), df.getCodepage()));
                                } else { // TODO review and validate. ad-hoc fix
                                    df.setBody(ConvertUtils.str2data(m_sbCollectChars.toString()));
                                }
                            }
                            
                            m_sbCollectChars = null; // stop collecting
                        } catch (DigiDocException ex) {
                            SAXDigiDocException.handleException(ex);
                        }
                        // this would throw away whitespace so calculate digest before it
                        //df.setBody(Base64Util.decode(m_sbCollectChars.toString()));
                    }

                    m_bCollectDigest = false;
                }
            }
            
            // </SignedInfo>
            if (qName.equals("SignedInfo")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                // calculate digest over the original
                // XML form of SignedInfo block and save it
                try {
                    Signature sig = getLastSignature();
                    SignedInfo si = sig.getSignedInfo();
                    //debugWriteFile("SigInfo1.xml", m_sbCollectChars.toString());

                    byte[] bCanSI = canonicalizationService.canonicalize(ConvertUtils.str2data(m_sbCollectChars.toString(), "UTF-8"),
                            SignedDoc.CANONICALIZATION_METHOD_20010315);
                    si.setOrigDigest(DDUtils.digest(bCanSI));
                    m_sbCollectChars = null; // stop collecting
                    //debugWriteFile("SigInfo2.xml", si.toString());
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }

            }
            
            // </SignedProperties>
            if (qName.equals("SignedProperties")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                // calculate digest over the original
                // XML form of SignedInfo block and save it
                //debugWriteFile("SigProps-orig.xml", m_sbCollectChars.toString());
                try {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    String sigProp = m_sbCollectChars.toString();
                    //debugWriteFile("SigProp1.xml", sigProp);
                    //System.out.println("SigProp1: " + sigProp.length() 
                    //    + " digest: " + Base64Util.encode(SignedDoc.digest(sigProp.getBytes())));
                    byte[] bCanProp = canonicalizationService.canonicalize(ConvertUtils.str2data(sigProp, "UTF-8"),
                            SignedDoc.CANONICALIZATION_METHOD_20010315);
                    //debugWriteFile("SigProp2.xml", new String(bCanProp));
                    sp.setOrigDigest(DDUtils.digest(bCanProp));
                    //System.out.println("Digest: " + Base64Util.encode(SignedDoc.digest(bCanProp)));
                    //System.out.println("SigProp2: " + sp.toString());
                    m_sbCollectChars = null; // stop collecting
                    CertID cid = sig.getCertIdOfType(CertID.CERTID_TYPE_SIGNER);
                    if (cid != null) {
                        /*System.out.println("CID: " + cid.getId() + " serial: " + cid.getSerial() +
                                " alg: " + cid.getDigestAlgorithm() + " diglen: " +
                                ((cid.getDigestValue() == null) ? 0 : cid.getDigestValue().length));*/
                        if (cid.getId() != null)
                            sp.setCertId(cid.getId());
                        else if (!sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_3))
                            sp.setCertId(sig.getId() + "-CERTINFO");
                        sp.setCertSerial(cid.getSerial());
                        sp.setCertDigestAlgorithm(cid.getDigestAlgorithm());
                        if (cid.getDigestValue() != null) {
                            sp.setCertDigestValue(cid.getDigestValue());
                        } 
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </SignatureValue>
            if (qName.equals("SignatureValue")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                m_strSigValTs = m_sbCollectChars.toString();
                //System.out.println("SigValTS mode: " + m_nCollectMode + "\n---\n" + m_strSigValTs + "\n---\n");           
                m_sbCollectChars = null; // stop collecting             
            }
            
            // </CompleteRevocationRefs>
            if (qName.equals("CompleteRevocationRefs")) {
                if (m_nCollectMode > 0) m_nCollectMode--;
                if (m_sbCollectChars != null)
                    m_strSigAndRefsTs = m_strSigValTs + m_sbCollectChars.toString();
                //System.out.println("SigAndRefsTs mode: " + m_nCollectMode + "\n---\n" + m_strSigAndRefsTs + "\n---\n");
                m_sbCollectChars = null; // stop collecting         
            }
            
            // </Signature>
            if (qName.equals("Signature")) {
                if (m_nCollectMode == 0) {
                    if (LOG.isTraceEnabled()) 
                        LOG.trace("End collecting <Signature>");
                    try {
                        Signature sig = getLastSignature();
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("Set sig content:\n---\n" + m_sbCollectSignature.toString() + "\n---\n");
                        } 
                        if (m_sbCollectSignature != null) {
                            sig.setOrigContent(ConvertUtils.str2data(m_sbCollectSignature.toString(), "UTF-8"));
                            if (LOG.isTraceEnabled()) 
                                LOG.trace("SIG orig content set: " + sig.getId() + " len: " + ((sig.getOrigContent() == null) ? 0 : sig.getOrigContent().length)); 
                            //debugWriteFile("SIG-" + sig.getId() + ".txt", m_sbCollectSignature.toString()); 
                            m_sbCollectSignature = null; // reset collecting
                        }
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
            }
            
            // </SignatureTimeStamp>
            if (qName.equals("SignatureTimeStamp")) {
                if (LOG.isTraceEnabled())
                        LOG.trace("End collecting <SignatureTimeStamp>");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
                    if (ts != null && m_strSigValTs != null) {
                        //System.out.println("SigValTS \n---\n" + m_strSigValTs + "\n---\n");
                        byte[] bCanXml = canonicalizationService.canonicalize(ConvertUtils.str2data(m_strSigValTs, "UTF-8"),
                                SignedDoc.CANONICALIZATION_METHOD_20010315);
                        byte[] hash = DDUtils.digest(bCanXml);
                        //System.out.println("SigValTS hash: " + Base64Util.encode(hash));
                        //debugWriteFile("SigProp2.xml", new String(bCanProp));
                        ts.setHash(hash);                   
                    }               
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </SigAndRefsTimeStamp>
            if (qName.equals("SigAndRefsTimeStamp")) {
                if (LOG.isTraceEnabled())
                        LOG.trace("End collecting <SigAndRefsTimeStamp>");
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = sig.getTimestampInfoOfType(TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS);
                    if (ts != null && m_strSigAndRefsTs != null) {
                        String canXml = "<a>" + m_strSigAndRefsTs + "</a>";
                        //System.out.println("SigAndRefsTS \n---\n" + m_strSigAndRefsTs + "\n---\n");
                        byte[] bCanXml = canonicalizationService.canonicalize(ConvertUtils.str2data(canXml, "UTF-8"),
                                SignedDoc.CANONICALIZATION_METHOD_20010315);
                        canXml = new String(bCanXml, "UTF-8");
                        canXml = canXml.substring(3, canXml.length() - 4);
                        //System.out.println("canonical \n---\n" + canXml + "\n---\n");
                        //debugWriteFile("SigProp2.xml", new String(bCanProp));
                        byte[] hash = DDUtils.digest(ConvertUtils.str2data(canXml, "UTF-8"));
                        //System.out.println("SigAndRefsTS hash: " + Base64Util.encode(hash));
                        ts.setHash(hash);                   
                    }       
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                } catch(Exception ex) {
                    //SAXDigiDocException.handleException(ex);
                }
            }
            
            // the following stuff is used also in
            // collect mode level 1 because it can be part 
            // of SignedInfo or SignedProperties
            if (m_nCollectMode == 1) {
                // </SigningTime>
                if (qName.equals("SigningTime")) {
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
                if (qName.equals("ClaimedRole")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    sp.addClaimedRole(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </City>
                if (qName.equals("City")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setCity(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </StateOrProvince>
                if (qName.equals("StateOrProvince")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setStateOrProvince(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </CountryName>
                if (qName.equals("CountryName")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setCountryName(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }
                // </PostalCode>
                if (qName.equals("PostalCode")) {
                    Signature sig = getLastSignature();
                    SignedProperties sp = sig.getSignedProperties();
                    SignatureProductionPlace spp = sp.getSignatureProductionPlace();
                    spp.setPostalCode(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                }

            } // level 1  
            
            // the following is collected on any level
            // </DigestValue>
            if (qName.equals("DigestValue")) {
                try {
                    //System.out.println("DIGEST: " + (m_sbCollectItem != null ? m_sbCollectItem.toString() : "NULL"));
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
                        if (cid != null)
                            cid.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        m_sbCollectItem = null; // stop collecting
                    } else if (m_tags.search("CompleteCertificateRefs") != -1) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteCertificateRefs crefs = up.getCompleteCertificateRefs();
                        CertID cid = crefs.getLastCertId();
                        if (cid != null)
                            cid.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        //System.out.println("CertID: " + cid.getId() + " digest: " + m_sbCollectItem.toString());
                        m_sbCollectItem = null; // stop collecting
                    } else if (m_tags.search("CompleteRevocationRefs") != -1) {
                        Signature sig = getLastSignature();
                        UnsignedProperties up = sig.getUnsignedProperties();
                        CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                        rrefs.setDigestValue(Base64Util.decode(m_sbCollectItem.toString()));
                        m_sbCollectItem = null; // stop collecting
                    }
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </IssuerSerial>
            if (qName.equals("IssuerSerial")
                && !doc.getVersion().equals(SignedDoc.VERSION_1_3)
                && !doc.getVersion().equals(SignedDoc.VERSION_1_4)) {
                try {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getLastCertId();
                    if (cid != null)
                        cid.setSerial(ConvertUtils.string2bigint(m_sbCollectItem.toString()));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </X509SerialNumber>
            if (qName.equals("X509SerialNumber")
                && (doc.getVersion().equals(SignedDoc.VERSION_1_3)
                || doc.getVersion().equals(SignedDoc.VERSION_1_4))) {
                try {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getLastCertId();
                    if (cid != null)
                        cid.setSerial(ConvertUtils.string2bigint(m_sbCollectItem.toString()));
                    //System.out.println("X509SerialNumber: " + cid.getSerial() + " type: " + cid.getType());
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </X509IssuerName>
            if (qName.equals("X509IssuerName")
                && (doc.getVersion().equals(SignedDoc.VERSION_1_3)
                || doc.getVersion().equals(SignedDoc.VERSION_1_4))) {
                try {
                    Signature sig = getLastSignature();
                    CertID cid = sig.getLastCertId();
                    String s = m_sbCollectItem.toString();
                    if (cid != null)
                        cid.setIssuer(s);
                    //System.out.println("X509IssuerName: " + s + " type: " + cid.getType() + " nr: " + cid.getSerial());
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            //</EncapsulatedTimeStamp>
            if (qName.equals("EncapsulatedTimeStamp")) {
                try {
                    Signature sig = getLastSignature();
                    TimestampInfo ts = sig.getLastTimestampInfo();
                    try {
                        //System.out.println("\n--TS_RESP--\n" + m_sbCollectItem.toString() + "\n--TS_RESP--\n");
                        ts.setTimeStampResponse(new TimeStampResponse(Base64Util.decode(m_sbCollectItem.toString())));
                        //ts.setTimeStampToken(new TimeStampToken(new CMSSignedData(Base64Util.decode(m_sbCollectItem.toString()))));
                    } catch(TSPException ex) {
                        throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_RESP, "Invalid timestamp response", ex);
                    } catch(IOException ex) {
                        throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_RESP, "Invalid timestamp response", ex);
                    }
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </ResponderID>
            if (qName.equals("ResponderID")) {
                try {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    rrefs.setResponderId(m_sbCollectItem.toString());
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // </ProducedAt>
            if (qName.equals("ProducedAt")) {
                try {
                    Signature sig = getLastSignature();
                    UnsignedProperties up = sig.getUnsignedProperties();
                    CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                    rrefs.setProducedAt(ConvertUtils.string2date(m_sbCollectItem.toString(), doc));
                    m_sbCollectItem = null; // stop collecting
                } catch (DigiDocException ex) {
                    SAXDigiDocException.handleException(ex);
                }
            }
            
            // the following stuff is ignored in collect mode
            // because it can only be the content of a higher element
            //if (m_nCollectMode == 0) {
                // </SignatureValue>
                if (qName.equals("SignatureValue")) {
                    try {
                        Signature sig = getLastSignature();
                        SignatureValue sv = sig.getSignatureValue();
                        //debugWriteFile("SigVal.txt", m_sbCollectItem.toString());
                        //System.out.println("SIGVAL mode: " + m_nCollectMode + ":\n--\n" + (m_sbCollectItem != null ? m_sbCollectItem.toString() : "NULL"));
                        sv.setValue(Base64Util.decode(m_sbCollectItem.toString().trim()));
                        m_sbCollectItem = null; // stop collecting
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }
                
                // </X509Certificate>
                if (qName.equals("X509Certificate")) {
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
                if (qName.equals("EncapsulatedX509Certificate")) {
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
                if (qName.equals("EncapsulatedOCSPValue")) {
                    try {
                        Signature sig = getLastSignature();
                        // first we have to find correct certid and certvalue types
                        findCertIDandCertValueTypes(sig);
                        UnsignedProperties up = sig.getUnsignedProperties();
                        Notary not = up.getNotary();
                        not.setOcspResponseData(Base64Util.decode(m_sbCollectItem.toString()));
                        notaryService.parseAndVerifyResponse(sig, not);
                        // in 1.1 we had bad OCPS digest
                        if (doc.getVersion().equals(SignedDoc.VERSION_1_1)) {
                            CompleteRevocationRefs rrefs = up.getCompleteRevocationRefs();
                            rrefs.setDigestValue(DDUtils.digest(not.getOcspResponseData()));
                        }
                        m_sbCollectItem = null; // stop collecting
                    } catch (DigiDocException ex) {
                        SAXDigiDocException.handleException(ex);
                    }
                }

            //} // if (m_nCollectMode == 0)
        }

        public void characters(char buf[], int offset, int len) throws SAXException {
            String s = new String(buf, offset, len);
            // just collect the data since it could
            // be on many lines and be processed in many events

            if (LOG.isTraceEnabled()) {
                LOG.trace("chars collectChars:" + (m_sbCollectChars != null) 
                        + " collectItem:" + (m_sbCollectItem != null) 
                        + " '" + s.replace("\n", "\\n") + "'");
            }
            
            if (m_sbCollectItem != null) {
                m_sbCollectItem.append(s);
            }
            
            if (m_sbCollectChars != null) {
                m_sbCollectChars.append(s);
            }
            
            if (m_sbCollectSignature != null) {
                m_sbCollectSignature.append(s);
            }
            
            if (m_digest != null && m_bCollectDigest) {
                updateDigest(s.getBytes());
            }
            
            try {
                if (dataFileCacheOutStream != null) {                    
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("Writing dataFile to cache stream");
                    } 

                    dataFileCacheOutStream.write(ConvertUtils.str2data(s)); // TODO don't "middle-convert" to string
                }
            } catch (IOException ex) {
                SAXDigiDocException.handleException(ex);
            }
        }

        public Signature getLastSignature() {
            return doc.getLastSignature();
        }

        private void updateDigest(byte[] data) {
            if (m_digest == null) {
                try {
                    m_digest = MessageDigest.getInstance("SHA-1");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }

            m_digest.update(data);
        }
        
        private void findCertIDandCertValueTypes(Signature sig)
        {
            if (LOG.isTraceEnabled())
                LOG.trace("Sig: " + sig.getId() + " certids: " + sig.countCertIDs());
            for(int i = 0; (sig != null) && (i < sig.countCertIDs()); i++) {
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
                                    LOG.trace("CertId type: " + cid.getType() + " nr: " + cid.getSerial() + " cval: " + cval.getId() + " CN: " + cn);
                                if (notaryService.isKnownOCSPCert(cn)) {
                                    if (LOG.isInfoEnabled())
                                        LOG.trace("Cert: " + cn + " is OCSP responders cert");
                                    cid.setType(CertID.CERTID_TYPE_RESPONDER);
                                    cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                                }
                                if (ConvertUtils.isKnownTSACert(cn)) {
                                    if (LOG.isTraceEnabled())
                                        LOG.trace("Cert: " + cn + " is TSA cert");
                                    cid.setType(CertID.CERTID_TYPE_TSA);
                                    cval.setType(CertValue.CERTVAL_TYPE_TSA);
                                    if (LOG.isTraceEnabled())
                                        LOG.trace("CertId: " + cid.getId() + " type: " + cid.getType() + " nr: " + cid.getSerial());
                                }
                            } catch(DigiDocException ex) {
                                LOG.error("Error setting type on certid or certval: " + cn);
                            }
                        }
                    }
                    
                } // for i < sig.countCertIDs()
                if (LOG.isTraceEnabled())
                  LOG.trace("Sig: " + sig.getId() + " certvals: " + sig.countCertValues());
                for(int i = 0; (sig != null) && (i < sig.countCertValues()); i++) {
                    CertValue cval = sig.getCertValue(i);
                    if (LOG.isTraceEnabled())
                        LOG.trace("CertValue: " + cval.getId() + " type: " + cval.getType());
                    if (cval.getType() == CertValue.CERTVAL_TYPE_UNKNOWN) {
                        String cn = null;
                        try {
                            cn = DDUtils.
                            getCommonName(cval.getCert().getSubjectDN().getName());
                            if (notaryService.isKnownOCSPCert(cn)) {
                                if (LOG.isTraceEnabled())
                                    LOG.trace("Cert: " + cn + " is OCSP responders cert");
                                cval.setType(CertValue.CERTVAL_TYPE_RESPONDER);
                            }
                            if (ConvertUtils.isKnownTSACert(cn)) {
                                if (LOG.isTraceEnabled())
                                    LOG.trace("Cert: " + cn + " is TSA cert");
                                cval.setType(CertValue.CERTVAL_TYPE_TSA);
                            }
                        } catch(DigiDocException ex) {
                            LOG.error("Error setting type on certid or certval: " + cn);
                        }                   
                    }
                }
        }

        /**
         * Helper method to calculate the digest result and 
         * reset digest
         * @return sha-1 digest value
         */
        private byte[] getDigest() {
            byte [] digest = null;
            // if not inited yet then initialize digest
            digest = m_digest.digest();
            m_digest = null; // reset for next calculation
            return digest;
        }

        /**
         * Helper method to canonicalize a piece of xml
         * @param xml data to be canonicalized
         * @return canonicalized xml
         */
        private String canonicalizeXml(String xml) {
            try {
                return new String(canonicalizationService.canonicalize(xml.getBytes("UTF-8"), SignedDoc.CANONICALIZATION_METHOD_20010315), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            } catch (DigiDocException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
