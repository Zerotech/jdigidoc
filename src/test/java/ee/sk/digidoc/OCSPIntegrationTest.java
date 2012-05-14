package ee.sk.digidoc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;

import org.junit.Test;

import ee.sk.digidoc.services.BouncyCastleNotaryServiceImpl;
import ee.sk.digidoc.services.CAServiceImpl;
import ee.sk.digidoc.services.CRLService;
import ee.sk.digidoc.services.CRLServiceImpl;

public class OCSPIntegrationTest {

    /**
     * http://www.id.ee/kehtivuskinnitus
     */
    @Test
    public void testOKCert() throws Exception {
        CRLService crlService = new CRLServiceImpl();
        CAServiceImpl caService = new CAServiceImpl();
        
        ArrayList<String> caCerts = new ArrayList<String>();
        caCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        caService.setCACerts(caCerts);
        
        BouncyCastleNotaryServiceImpl notaryService = new BouncyCastleNotaryServiceImpl(crlService, caService, "http://ocsp.sk.ee", true, "/Users/siim/Downloads/118919.p12d", "aD37OiSX");
        
        HashSet<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        notaryService.setOCSPCerts(ocspCerts);
        
        X509Certificate c = getAuthCertificate();

        notaryService.checkCertificate(c);

    }
    
    private X509Certificate getAuthCertificate() {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("src/test/data/37807256017_auth.cer"));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    
    
}
