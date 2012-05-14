package ee.sk.digidoc;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import ee.sk.digidoc.services.BouncyCastleNotaryServiceImpl;
import ee.sk.digidoc.services.CAServiceImpl;
import ee.sk.digidoc.services.CRLService;
import ee.sk.digidoc.services.CRLServiceImpl;
import ee.sk.digidoc.services.DigiDocService;
import ee.sk.digidoc.services.SAXDigidocServiceImpl;
import ee.sk.digidoc.services.TinyXMLCanonicalizationServiceImpl;
import ee.sk.digidoc.services.VerificationServiceImpl;

public class DigiDocServiceTests {

    @Test
    public void testReadSignatures() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        CAServiceImpl caService = new CAServiceImpl();
        
        List<String> cac = new ArrayList<String>();
        cac.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        caService.setCACerts(cac);
        
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, caService, "http://ocsp.sk.ee", false, null, null);
        
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        notaryService.setOCSPCerts(ocspCerts);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        for (int i = 0; i < sd.countSignatures(); i++) {
            Signature s = sd.getSignature(i);
            System.out.println(s.getKeyInfo().getSubjectFirstName());
            System.out.println(s.getKeyInfo().getSubjectLastName());
            System.out.println(s.getKeyInfo().getSubjectPersonalCode());
        }
        
        VerificationServiceImpl verificationService = new VerificationServiceImpl(caService, notaryService, "RSA//");
        
        verificationService.verify(sd, true, true);
    }
    
    @Test
    public void verifyOlderDocument() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        
        CAServiceImpl caService = new CAServiceImpl();
        
        List<String> cac = new ArrayList<String>();
        cac.add("jar:///ee/sk/digidoc/certs/ESTEID-SK.PEM.cer"); // since 2002, for checking older ddocs
        cac.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007.PEM.cer");
        cac.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        caService.setCACerts(cac);
        
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, caService, "http://ocsp.sk.ee", false, null, null);
        
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007 RESPONDER.pem.cer");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK_2007_OCSP_RESPONDER_2010.pem");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        notaryService.setOCSPCerts(ocspCerts);
        
        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/Hange_nr._9333.ddoc");
        
        for (int i = 0; i < sd.countSignatures(); i++) {
            Signature s = sd.getSignature(i);
            System.out.println(s.getKeyInfo().getSubjectFirstName());
            System.out.println(s.getKeyInfo().getSubjectLastName());
            System.out.println(s.getKeyInfo().getSubjectPersonalCode());
        }
        
        VerificationServiceImpl verificationService = new VerificationServiceImpl(caService, notaryService, "RSA//");
        
        verificationService.verify(sd, true, true);
    }
    
    
    
    
    
    
}
