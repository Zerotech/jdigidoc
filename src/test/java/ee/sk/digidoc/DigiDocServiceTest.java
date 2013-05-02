package ee.sk.digidoc;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import ee.sk.digidoc.services.BouncyCastleNotaryServiceImpl;
import ee.sk.digidoc.services.BouncyCastleTimestampService;
import ee.sk.digidoc.services.CRLService;
import ee.sk.digidoc.services.CRLServiceImpl;
import ee.sk.digidoc.services.DigiDocService;
import ee.sk.digidoc.services.SAXDigidocServiceImpl;
import ee.sk.digidoc.services.TinyXMLCanonicalizationServiceImpl;
import ee.sk.digidoc.services.TrustServiceImpl;
import ee.sk.digidoc.services.VerificationServiceImpl;

public class DigiDocServiceTest {

    @Test
    public void testReadDDocFromFile() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", false, null, null, 30000, false);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService,
                        new BouncyCastleTimestampService());
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        VerificationServiceImpl verificationService = new VerificationServiceImpl(trustService, notaryService,
                        new TinyXMLCanonicalizationServiceImpl());
        
        verificationService.verify(sd, true, true);
    }
    
    @Test
    public void verifyOlderDocument() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", false, null, null, 30000, false);
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService,
                        new BouncyCastleTimestampService());
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/Hange_nr._9333.ddoc");
        
        VerificationServiceImpl verificationService = new VerificationServiceImpl(trustService, notaryService,
                        new TinyXMLCanonicalizationServiceImpl());
        
        verificationService.verify(sd, true, true);
    }
    
    @Test
    public void testReadDDocFromStream() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", false, null, null, 30000, false);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService,
                        new BouncyCastleTimestampService());
        
        InputStream stream = new FileInputStream("src/test/data/volikiri.ddoc");
        
        SignedDoc sd = dds.readSignedDocFromStream(stream);
        
        VerificationServiceImpl verificationService = new VerificationServiceImpl(trustService, notaryService,
                        new TinyXMLCanonicalizationServiceImpl());
        
        verificationService.verify(sd, true, true);
    }
    
    @Test
    public void testReadBDocFromFile() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", false, null, null, 30000, false);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService,
                        new BouncyCastleTimestampService());
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/attachment.bdoc");
        
        VerificationServiceImpl verificationService = new VerificationServiceImpl(trustService, notaryService,
                        new TinyXMLCanonicalizationServiceImpl());
        
        verificationService.verify(sd, true, true);
    }

    @Test(expected = ee.sk.digidoc.DigiDocException.class)
    public void testReadDDocNullFilename() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", false, null, null, 30000, false);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService,
                        new BouncyCastleTimestampService());
        
        dds.readSignedDoc(null);
    }
    
    @Test(expected = ee.sk.digidoc.DigiDocException.class)
    public void testReadDDocNullStream() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", false, null, null, 30000, false);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService,
                        new BouncyCastleTimestampService());
        
        dds.readSignedDocFromStream(null);
    }
    
    @Test
    public void readSignatureFromDdoc() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", false, null, null, 30000, false);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService,
                        new BouncyCastleTimestampService());
        
        InputStream stream = new FileInputStream("src/test/data/volikiri.ddoc");
        
        Signature signature = dds.readSignature(null, stream);
        
        assertNotNull(signature);
    }

    private TrustServiceImpl getTrustService() {
        String fileDir = "src/main/resources/ee/sk/digidoc/VTSL-EE.xml";
        TrustServiceImpl trustService = new TrustServiceImpl(fileDir, true);
        
        ArrayList<String> caCerts = new ArrayList<String>();
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007.PEM.cer");
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK.PEM.cer"); // since 2002, for checking older ddocs
        
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007 RESPONDER.pem.cer");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK_2007_OCSP_RESPONDER_2010.pem");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        
        trustService.setCACerts(caCerts);
        trustService.setOCSPCerts(ocspCerts);
        
        return trustService;
    }
}
