package ee.sk.digidoc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ee.sk.digidoc.services.BouncyCastleNotaryServiceImpl;
import ee.sk.digidoc.services.CAServiceImpl;
import ee.sk.digidoc.services.CRLService;
import ee.sk.digidoc.services.CRLServiceImpl;
import ee.sk.digidoc.services.DigiDocService;
import ee.sk.digidoc.services.SAXDigidocServiceImpl;
import ee.sk.digidoc.services.TinyXMLCanonicalizationServiceImpl;

public class DigiDocServiceTests {

    @Test
    public void testReadSignatures() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        CAServiceImpl caService = new CAServiceImpl();
        
        List<String> cac = new ArrayList<String>();
        cac.add("jar:///certs/EID-SK.crt");
        cac.add("jar:///certs/EID-SK 2007.crt");
        cac.add("jar:///certs/ESTEID-SK.crt");
        cac.add("jar:///certs/ESTEID-SK 2007.crt");
        cac.add("jar:///certs/JUUR-SK.crt");
        cac.add("jar:///certs/KLASS3-SK.crt");
        cac.add("/Users/siim/EECCRCA.pem.cer");
        cac.add("/Users/siim/ESTEID-SK_2011.pem.cer");
        
        caService.setCACerts(cac);
        
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, caService, false);
        
        Map<String, String> ocspCerts = new HashMap<String, String>();
        ocspCerts.put("ESTEID-SK 2007 OCSP RESPONDER 2010", "jar:///certs/ESTEID-SK 2007 OCSP 2010.crt");
        ocspCerts.put("SK OCSP RESPONDER 2011",             "/Users/siim/SK_OCSP_RESPONDER_2011.pem.cer");
        notaryService.setOCSPCerts(ocspCerts);
        
        Map<String, String> ocspcaCerts = new HashMap<String, String>();
        ocspcaCerts.put("ESTEID-SK 2007", "jar:///certs/ESTEID-SK 2007 OCSP 2010.crt");
        ocspcaCerts.put("ESTEID-SK 2011", "/Users/siim/SK_OCSP_RESPONDER_2011.pem.cer");
        notaryService.setOCSPCACerts(ocspcaCerts);

        DigiDocService dds = new SAXDigidocServiceImpl(new TinyXMLCanonicalizationServiceImpl(), notaryService);
        
        SignedDoc sd = dds.readSignedDoc("/Users/siim/tooleping_mikk.ddoc");
        
        for (int i = 0; i < sd.countSignatures(); i++) {
            Signature s = sd.getSignature(i);
            System.out.println(s.getKeyInfo().getSubjectFirstName());
            System.out.println(s.getKeyInfo().getSubjectLastName());
            System.out.println(s.getKeyInfo().getSubjectPersonalCode());
        }
    }
    
}
