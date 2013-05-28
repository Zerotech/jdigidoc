package ee.sk.digidoc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import ee.sk.digidoc.services.BouncyCastleNotaryServiceImpl;
import ee.sk.digidoc.services.CRLService;
import ee.sk.digidoc.services.CRLServiceImpl;
import ee.sk.digidoc.services.TrustServiceImpl;

public class OCSPIntegrationTest {

    /**
     * http://www.id.ee/kehtivuskinnitus
     */
    @Test
    public void testOKCert() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        TrustServiceImpl trustService = getTRustService();
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, trustService,
                        "http://ocsp.sk.ee", true, "/Users/piret/Documents/48809164211.p12", "aF4h7yLpsv9nA", 30000,
                        false);

        X509Certificate c = getAuthCertificate();
        
        notaryService.checkCertificate(c);
        
    }
    
    private X509Certificate getAuthCertificate() {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                            new FileInputStream("src/test/data/37807256017_auth.cer"));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    
    private TrustServiceImpl getTRustService() {
        String fileDir = "src/main/resources/ee/sk/digidoc/VTSL-EE.xml";
        
        TrustServiceImpl trustService = new TrustServiceImpl(fileDir, true);
        
        ArrayList<String> caCerts = new ArrayList<String>();
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        
        trustService.setCACerts(caCerts);
        trustService.setOCSPCerts(ocspCerts);
        
        return trustService;
    }
}
