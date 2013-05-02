package ee.sk.digidoc.tsl;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Stack;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.log4j.Logger;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.services.SAXDigiDocException;
import ee.sk.utils.Base64Util;
import ee.sk.utils.DDUtils;

/**
 * ETSI TS 102 231 V3.1.1. TSL xml format parser
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class TslParser extends DefaultHandler {
    
    public static Logger LOG = Logger.getLogger(TslParser.class);
    
    private Stack<String> tags;
    
    private TrustServiceStatusList tsl;
    
    private StringBuffer sbCollectItem;
    
    private MultiLangString mls;
    
    private TSPService tsps;
    
    private Quality qual;
    
    /**
     * Reads in a TSL file
     * 
     * @param is opened stream with TSL data
     *            The user must open and close it.
     * @return TSL
     */
    public TrustServiceStatusList readTSL(InputStream is) throws DigiDocException {
        // Use an instance of ourselves as the SAX event handler
        TslParser handler = this;
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        try {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(is, handler);
        } catch (SAXDigiDocException ex) {
            throw ex.getDigiDocException();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (tsl == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "This document is not in TSL format", null);
        return tsl;
    }

    /**
     * Start Document handler
     */
    public void startDocument() throws SAXException {
        tags = new Stack<String>();
    }
    
    /**
     * End Document handler
     */
    public void endDocument() throws SAXException {}
    
    private boolean findTagOnStack(String tag) {
        Enumeration<String> eTags = tags.elements();
        while (eTags.hasMoreElements()) {
            String t2 = (String) eTags.nextElement();
            if (t2.equals(tag)) return true;
        }
        return false;
    }
    
    /**
     * Start Element handler
     * 
     * @param namespaceURI namespace URI
     * @param lName local name
     * @param qName qualified name
     * @param attrs attributes
     */
    public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
                    throws SAXDigiDocException {
        String tag = qName;
        if (tag.indexOf(':') != -1) {
            tag = qName.substring(qName.indexOf(':') + 1);
        }
        tags.push(tag);
        sbCollectItem = new StringBuffer();
        
        // <TrustServiceStatusList>
        if (tag.equals("TrustServiceStatusList")) tsl = new TrustServiceStatusList();

        // <TSPService>
        if (tag.equals("TSPService")) {
            tsps = new TSPService();
            if (tsl != null) tsl.addTSPService(tsps);
        }
    }
    
    /**
     * End Element handler
     * 
     * @param namespaceURI namespace URI
     * @param lName local name
     * @param qName qualified name
     */
    public void endElement(String namespaceURI, String sName, String qName) throws SAXException {

        String tag = qName;

        if (tag.indexOf(':') != -1) {
            tag = qName.substring(qName.indexOf(':') + 1);
        }
        
        // </TSLType>
        if (tag.equals("TSLType")) {
            if (tsl != null) tsl.setType(sbCollectItem.toString());
        }

        // </URI>
        if (tag.equals("URI")) {
            if (mls != null) mls.setValue(sbCollectItem.toString());
            mls = null;
        }

        // </TSLLegalNotice>
        if (tag.equals("TSLLegalNotice")) {
            if (mls != null) mls.setValue(sbCollectItem.toString());
            mls = null;
        }

        // </ServiceTypeIdentifier>
        if (tag.equals("ServiceTypeIdentifier")) {
            if (tsps != null) tsps.setType(sbCollectItem.toString());
        }

        // </X509Certificate>
        if (tag.equals("X509Certificate")) {
            try {
                if (tsps != null && findTagOnStack("ServiceDigitalIdentity")) {
                    X509Certificate cert = DDUtils.readCertificate(Base64Util.decode(sbCollectItem.toString()));
                    if (cert != null) {
                        tsps.addCertificate(cert);
                        String sDn = DDUtils.convX509Name(cert.getIssuerX500Principal());
                        String sCn = DDUtils.getCommonName(sDn);
                        if (LOG.isDebugEnabled()) LOG.debug("DN: " + sDn + " CN: " + sCn);
                        tsps.setCaCN(sCn);
                    }
                }
            } catch (DigiDocException ex) {
                SAXDigiDocException.handleException(ex);
            }
        }

        // </X509SubjectName>
        if (tag.equals("X509SubjectName")) {
            if (tsps != null && findTagOnStack("DigitalId")) {
                String cn = DDUtils.getCommonName(sbCollectItem.toString());
                if (cn != null && cn.trim().length() > 0) tsps.setCN(cn);
            }
        }

        // </QualityName>
        if (tag.equals("QualityName")) {
            if (qual != null) qual.setName(sbCollectItem.toString());
        }

        // </QualityValue>
        if (tag.equals("QualityValue")) {
            if (qual != null) qual.setValue(Integer.parseInt(sbCollectItem.toString()));
        }

        // </ServiceSupplyPoint>
        if (tag.equals("ServiceSupplyPoint")) {
            if (tsps != null) tsps.addServiceAccessPoint(sbCollectItem.toString());
        }

        // </QualityElement>
        if (tag.equals("QualityElement")) qual = null;

        // </TSPService>
        if (tag.equals("TSPService")) tsps = null;

        sbCollectItem = null;
    }
    
    /**
     * SAX characters event handler
     * 
     * @param buf received bytes array
     * @param offset offset to the array
     * @param len length of data
     */
    public void characters(char buf[], int offset, int len) throws SAXException {
        String s = new String(buf, offset, len);
        if (s != null && sbCollectItem != null) sbCollectItem.append(s);
    }
}
