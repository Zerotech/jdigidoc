package ee.sk.digidoc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ee.sk.digidoc.services.TrustServiceImpl;

public class TrustServiceTest {
    
    private TrustServiceImpl service;
    
    @Before
    public void setUp() {
        String fileDir = "src/main/resources/ee/sk/digidoc/VTSL-EE.xml";
        
        service = new TrustServiceImpl(fileDir, true);
        
        List<String> cac = new ArrayList<String>();
        cac.add("jar:///ee/sk/digidoc/certs/ESTEID-SK.PEM.cer");
        cac.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007.PEM.cer");
        cac.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2011.pem.cer");
        
        Set<String> ocspCerts = new HashSet<String>();
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK OCSP RESPONDER.PEM.cer");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK OCSP RESPONDER 2005.PEM.cer");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK 2007 RESPONDER.pem.cer");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/ESTEID-SK_2007_OCSP_RESPONDER_2010.pem");
        ocspCerts.add("jar:///ee/sk/digidoc/certs/SK OCSP RESPONDER 2011.pem.cer");
        
        service.setCACerts(cac);
        service.setOCSPCerts(ocspCerts);
    }
    
    @Test
    public void testfindCaForCert() {
        
        X509Certificate cert = service.findCaForCert(getAuthCertificate());
        
        assertNotNull(cert);
        
        service.setUseLocal(false);
        cert = service.findCaForCert(getAuthCertificate());
        
        assertNull(cert);
    }
    
    @Test
    public void testFindOcspByCN() {
        
        X509Certificate cert = service.findOcspByCN("ESTEID-SK 2007 OCSP RESPONDER");

        assertNotNull(cert);
    }
    
    @Test
    public void testFindOcspUrlForCert() {
        
        String url = service.findOcspUrlForCert(getAuthCertificate(), 0);
        
        assertNotNull(url);
        assertFalse(url.isEmpty());
        
        service.setUseLocal(false);
        url = service.findOcspUrlForCert(getAuthCertificate(), 0);
        
        assertNotNull(url);
        assertFalse(url.isEmpty());
        
        service.setUseLocal(true);
        url = service.findOcspUrlForCert(getAuthCertificate(), 1);
        
        assertNotNull(url);
        assertFalse(url.isEmpty());

    }
    
    @Test
    public void testFindOcspByCNAndSerialNr() {
        List<X509Certificate> certs = service.findOcspsByCNAndNr("ESTEID-SK 2007 OCSP RESPONDER", "1167923826");
        
        assertNotNull(certs);
        assertFalse(certs.isEmpty());
        
        certs = service.findOcspsByCNAndNr("ESTEID-SK 2007 OCSP RESPONDER", null);

        assertNotNull(certs);
        assertTrue(certs.isEmpty());

        service.setUseLocal(false);
        certs = service.findOcspsByCNAndNr("ESTEID-SK 2007 OCSP RESPONDER", "1167923826");
        
        assertNotNull(certs);
        assertFalse(certs.isEmpty());
    }

    private X509Certificate getAuthCertificate() {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                            new FileInputStream("src/test/data/37807256017_sign.cer"));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
