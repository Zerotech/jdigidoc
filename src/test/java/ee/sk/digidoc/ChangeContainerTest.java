package ee.sk.digidoc;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import ee.sk.digidoc.services.BouncyCastleNotaryServiceImpl;
import ee.sk.digidoc.services.BouncyCastleTimestampService;
import ee.sk.digidoc.services.CRLService;
import ee.sk.digidoc.services.CRLServiceImpl;
import ee.sk.digidoc.services.CanonicalizationService;
import ee.sk.digidoc.services.SAXDigidocServiceImpl;
import ee.sk.digidoc.services.TimestampService;
import ee.sk.digidoc.services.TinyXMLCanonicalizationServiceImpl;
import ee.sk.digidoc.services.TrustServiceImpl;

public class ChangeContainerTest {
    
    /**
     * Small files are not cached.
     */
    @Test
    public void parseAndWriteDDOCWithoutCache() throws Exception {
        CanonicalizationService cs = new TinyXMLCanonicalizationServiceImpl();
        TrustServiceImpl trustService = getTrustService();
        CRLService crlService = new CRLServiceImpl();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService, null,
                        false, null, null, 30000, false);
        TimestampService timeStampService = new BouncyCastleTimestampService();
        
        SAXDigidocServiceImpl dds = new SAXDigidocServiceImpl(cs, notaryService, timeStampService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        sd.writeToFile(new File("target/parseAndWriteDDOCTest.ddoc"));
    }

    /**
     * Lage files are cached.
     */
    @Test
    public void parseAndWriteDDOCWithCache() throws Exception {
        CanonicalizationService cs = new TinyXMLCanonicalizationServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        CRLService crlService = new CRLServiceImpl();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService, null,
                        false, null, null, 30000, false);
        TimestampService timeStampService = new BouncyCastleTimestampService();
        
        SAXDigidocServiceImpl dds = new SAXDigidocServiceImpl(cs, notaryService, timeStampService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/Hange_nr._9333.ddoc");
        
        sd.writeToFile(new File("target/parseAndWriteDDOCTest.ddoc"));
    }
    
    @Test
    public void removeSignature() throws Exception {
        CanonicalizationService cs = new TinyXMLCanonicalizationServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        CRLService crlService = new CRLServiceImpl();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService, null,
                        false, null, null, 30000, false);
        TimestampService timeStampService = new BouncyCastleTimestampService();
        
        SAXDigidocServiceImpl dds = new SAXDigidocServiceImpl(cs, notaryService, timeStampService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        Assert.assertEquals(1, sd.countSignatures());
        
        sd.removeSignature(0);

        Assert.assertEquals(0, sd.countSignatures());
        
        sd.writeToFile(new File("target/removeSignature_signature_removed.ddoc"));
    }
    
    @Test
    public void signUnsignedDoc() throws Exception {
        CanonicalizationService cs = new TinyXMLCanonicalizationServiceImpl();
        
        TrustServiceImpl trustService = getTrustService();
        CRLService crlService = new CRLServiceImpl();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService, null,
                        false, null, null, 30000, false);
        TimestampService timeStampService = new BouncyCastleTimestampService();
        
        SAXDigidocServiceImpl dds = new SAXDigidocServiceImpl(cs, notaryService, timeStampService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        Assert.assertEquals(1, sd.countSignatures());
        
        sd.removeSignature(0);
        
        Assert.assertEquals(0, sd.countSignatures());
        
        InputStream is = new FileInputStream("src/test/data/volikiri.ddoc");
        
        Signature sig = dds.readSignature(sd, is);
        
        sd.addSignature(sig);
        
        Assert.assertEquals(1, sd.countSignatures());
    }

    private TrustServiceImpl getTrustService() {
        String fileDir = "src/main/resources/ee/sk/digidoc/VTSL-EE.xml";
        
        TrustServiceImpl trustService = new TrustServiceImpl(fileDir, true);
        
        ArrayList<String> caCerts = new ArrayList<String>();
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007.PEM.cer");
        
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK_2007_OCSP_RESPONDER_2010.pem");
        
        trustService.setCACerts(caCerts);
        trustService.setOCSPCerts(ocspCerts);
        
        return trustService;
    }
    
}
