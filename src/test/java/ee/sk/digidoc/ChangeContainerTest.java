package ee.sk.digidoc;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import ee.sk.digidoc.services.BouncyCastleNotaryServiceImpl;
import ee.sk.digidoc.services.CAServiceImpl;
import ee.sk.digidoc.services.CRLService;
import ee.sk.digidoc.services.CRLServiceImpl;
import ee.sk.digidoc.services.CanonicalizationService;
import ee.sk.digidoc.services.SAXDigidocServiceImpl;
import ee.sk.digidoc.services.TinyXMLCanonicalizationServiceImpl;

public class ChangeContainerTest {

    
    /**
     * Small files are not cached.
     */
    @Test
    public void parseAndWriteDDOCWithoutCache() throws Exception {
        CanonicalizationService cs = new TinyXMLCanonicalizationServiceImpl();
        
        CAServiceImpl caService = new CAServiceImpl();
        ArrayList<String> caCerts = new ArrayList<String>();
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        caService.setCACerts(caCerts);
        
        CRLService crlService = new CRLServiceImpl();
        
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, caService, null, false, null, null);
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        notaryService.setOCSPCerts(ocspCerts);
        
        SAXDigidocServiceImpl dds = new SAXDigidocServiceImpl(cs, notaryService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        sd.writeToFile(new File("target/parseAndWriteDDOCTest.ddoc"));
    }

    /**
     * Lage files are cached.
     */
    @Test
    public void parseAndWriteDDOCWithCache() throws Exception {
        CanonicalizationService cs = new TinyXMLCanonicalizationServiceImpl();
        
        CAServiceImpl caService = new CAServiceImpl();
        ArrayList<String> caCerts = new ArrayList<String>();
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007.PEM.cer");
        caService.setCACerts(caCerts);
        
        CRLService crlService = new CRLServiceImpl();
        
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, caService, null, false, null, null);
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK_2007_OCSP_RESPONDER_2010.pem");
        notaryService.setOCSPCerts(ocspCerts);
        
        SAXDigidocServiceImpl dds = new SAXDigidocServiceImpl(cs, notaryService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/Hange_nr._9333.ddoc");
        
        sd.writeToFile(new File("target/parseAndWriteDDOCTest.ddoc"));
    }

    
    @Test
    public void removeSignature() throws Exception {
        CanonicalizationService cs = new TinyXMLCanonicalizationServiceImpl();
        
        CAServiceImpl caService = new CAServiceImpl();
        ArrayList<String> caCerts = new ArrayList<String>();
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        caService.setCACerts(caCerts);
        
        CRLService crlService = new CRLServiceImpl();
        
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, caService, null, false, null, null);
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        notaryService.setOCSPCerts(ocspCerts);
        
        SAXDigidocServiceImpl dds = new SAXDigidocServiceImpl(cs, notaryService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        
        System.out.println(sd.getDataFile(0).getSize());
        
        Assert.assertEquals(1, sd.countSignatures());
        
        sd.removeSignature(0);

        Assert.assertEquals(0, sd.countSignatures());
        
        sd.writeToFile(new File("target/removeSignature_signature_removed.ddoc"));
    }
    
    
}
