package ee.sk.digidoc;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import ee.sk.digidoc.services.CanonicalizationService;
import ee.sk.digidoc.services.DigiDocService;
import ee.sk.digidoc.services.NotaryService;
import ee.sk.digidoc.services.TrustService;
import ee.sk.digidoc.services.VerificationServiceImpl;
import ee.sk.utils.ConvertUtils;

public class TestSpringContextAndConfIntegrationTest {

    private static final Logger LOG = Logger.getLogger(TestSpringContextAndConfIntegrationTest.class);
    
    @Test
    public void springContextComesUp() throws Exception {
        ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext("/ee/sk/digidoc/applicationContext.xml");
        DigiDocService dds = ctx.getBean(DigiDocService.class);
        dds.readSignedDoc("src/test/data/volikiri.ddoc");
    }
    
    /**
     * Print out as much readable (no byte[]) stuff as possible.
     * 
     * @throws Exception
     */
    @Test
    public void printOutDDocInformation() throws Exception {
        ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext("/ee/sk/digidoc/applicationContext.xml");
        DigiDocService dds = ctx.getBean(DigiDocService.class);
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        LOG.debug("format: " + sd.getFormat());
        LOG.debug("version: " + sd.getVersion());
        LOG.debug("=============================");
        LOG.debug("no of data files: " + sd.countDataFiles());
        for (int i = 0; i < sd.countDataFiles(); i++) {
            LOG.debug("===");
            DataFile df = sd.getDataFile(i);
            LOG.debug("id: " + df.getId());
            
            LOG.debug("filename: " + df.getFileName());
            
            LOG.debug("contentType: " + df.getContentType());
            LOG.debug("mimeType: " + df.getMimeType());
            LOG.debug("size: " + df.getSize());
            
            LOG.debug("digestType: " + df.getDigestType());
            LOG.debug("digestValue: " + df.getDigest());
            
            //LOG.debug("body: " + df.getBody());
            
            LOG.debug("initialCodepage: " + df.getCodepage());
            
            LOG.debug("datafile attributes: " + df.countAttributes());
            
            for (int j = 0; j < df.countAttributes(); j++) {
                DataFileAttribute dfa = df.getAttribute(j);
                LOG.debug("==");
                LOG.debug("datafile attribute name: " + dfa.getName());
                LOG.debug("datafile attribute value: " + dfa.getValue());
            }
        }
        
        LOG.debug("=============================");
        LOG.debug("no of signaturs: " + sd.countSignatures());
        
        for (int i = 0; i < sd.countSignatures(); i++) {
            Signature s = sd.getSignature(i);
            
            for (int j = 0; j < s.getSignedInfo().countReferences(); j++) {
                Reference r = s.getSignedInfo().getReference(j);
                LOG.debug("==");
                LOG.debug("reference uri: " + r.getUri());
                LOG.debug("reference digest algorithm: " + r.getDigestAlgorithm());
                LOG.debug("reference digest value: " + ConvertUtils.bin2hex(r.getDigestValue()));
                LOG.debug("reference transform algorithm: " + r.getTransformAlgorithm());
                LOG.debug("reference ref signedInfo: " + r.getSignedInfo());
            }
            
            LOG.debug("===");
            LOG.debug("signature id: " + s.getId());
            LOG.debug("signedinfo signature method: " + s.getSignedInfo().getSignatureMethod());
            LOG.debug("signedinfo canonicalization method: " + s.getSignedInfo().getCanonicalizationMethod());
            LOG.debug("signedinfo original digest: " + ConvertUtils.bin2hex(s.getSignedInfo().getOrigDigest()));
            LOG.debug("signedinfo references count: " + s.getSignedInfo().countReferences());
            
            LOG.debug("==");
            LOG.debug("signaturevalue id: " + s.getSignatureValue().getId());
            LOG.debug("signaturevalue value: " + ConvertUtils.bin2hex(s.getSignatureValue().getValue()));
            LOG.debug("==");
            
            LOG.debug("key info subject personal code: " + s.getKeyInfo().getSubjectPersonalCode());
            LOG.debug("key info subject first name: " + s.getKeyInfo().getSubjectFirstName());
            LOG.debug("key info subject last name: " + s.getKeyInfo().getSubjectLastName());
            
            LOG.debug("key info signer key exponent: " + s.getKeyInfo().getSignerKeyExponent());
            LOG.debug("key info signer key modulus: " + s.getKeyInfo().getSignerKeyModulus());
            LOG.debug("key info signer certificate: " + s.getKeyInfo().getSignersCertificate().getSubjectDN());
            LOG.debug("==");
            
            LOG.debug("signature signed properties id: " + s.getSignedProperties().getId());
            LOG.debug("signature signed properties target: " + s.getSignedProperties().getTarget());
            LOG.debug("signature signed properties signing time: " + s.getSignedProperties().getSigningTime());
            LOG.debug("signature signed properties cert digest algorithm: "
                            + s.getSignedProperties().getCertDigestAlgorithm());
            LOG.debug("signature signed properties cert id: " + s.getSignedProperties().getCertId());
            LOG.debug("signature signed properties cert digest value: "
                            + ConvertUtils.bin2hex(s.getSignedProperties().getCertDigestValue()));
            LOG.debug("signature signed properties cert serial: " + s.getSignedProperties().getCertSerial());
            LOG.debug("signature signed properties place city: "
                            + s.getSignedProperties().getSignatureProductionPlace().getCity());
            LOG.debug("signature signed properties place state: "
                            + s.getSignedProperties().getSignatureProductionPlace().getStateOrProvince());
            LOG.debug("signature signed properties place country: "
                            + s.getSignedProperties().getSignatureProductionPlace().getCountryName());
            LOG.debug("signature signed properties place zip: "
                            + s.getSignedProperties().getSignatureProductionPlace().getPostalCode());
            LOG.debug("signature signed properties claimed roles no: " + s.getSignedProperties().countClaimedRoles());
            
            for (int j = 0; j < s.getSignedProperties().countClaimedRoles(); j++) {
                LOG.debug("signature signed properties claimed role: " + s.getSignedProperties().getClaimedRole(j));
            }
            
            LOG.debug("signature signed properties Original digest: "
                            + ConvertUtils.bin2hex(s.getSignedProperties().getOrigDigest()));
            LOG.debug("signature signed properties signed data object properties: "
                            + s.getSignedProperties().getSignedDataObjectProperties());
            LOG.debug("signature signed properties data object format: "
                            + s.getSignedProperties().getDataObjectFormat());
            LOG.debug("==");
            
            LOG.debug("signature qualifying properties: " + s.getQualifyingProperties());
            LOG.debug("==");
            LOG.debug("signature unsigned properties complete revocation refs last ocsp ref uri: "
                            + s.getUnsignedProperties().getCompleteRevocationRefs().getLastOcspRef().getUri());
            LOG.debug("signature unsigned properties complete revocation refs last ocsp ref responderId: "
                            + s.getUnsignedProperties().getCompleteRevocationRefs().getLastOcspRef().getResponderId());
            LOG.debug("signature unsigned properties complete revocation refs last ocsp ref produced at: "
                            + s.getUnsignedProperties().getCompleteRevocationRefs().getLastOcspRef().getProducedAt());
            LOG.debug("signature unsigned properties complete revocation refs last ocsp ref digest algorithm: "
                            + s.getUnsignedProperties().getCompleteRevocationRefs().getLastOcspRef()
                                            .getDigestAlgorithm());
            LOG.debug("signature unsigned properties complete revocation refs last ocsp ref digest value: "
                            + ConvertUtils.bin2hex(s.getUnsignedProperties().getCompleteRevocationRefs()
                                            .getLastOcspRef().getDigestValue()));
            
            LOG.debug("signature unsigned properties notary id: " + s.getUnsignedProperties().getNotary().getId());
            LOG.debug("signature unsigned properties notary certnr: "
                            + s.getUnsignedProperties().getNotary().getCertNr());
            LOG.debug("signature unsigned properties notary responderid: "
                            + s.getUnsignedProperties().getNotary().getResponderId());
            LOG.debug("signature unsigned properties notary produced at: "
                            + s.getUnsignedProperties().getNotary().getProducedAt());
            LOG.debug("signature unsigned properties notary ocsp reponse data: "
                            + ConvertUtils.bin2hex(s.getUnsignedProperties().getNotary().getOcspResponseData()));
            
            //
            byte[] ocspdata = s.getUnsignedProperties().getNotary().getOcspResponseData();
            
            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(ocspdata));
            OCSPResponse resp = OCSPResponse.getInstance(aIn.readObject());
            ResponseBytes rBytes = ResponseBytes.getInstance(resp.getResponseBytes());
            LOG.debug("ocsp response: " + rBytes.getResponse());
            LOG.debug("ocsp response type: " + rBytes.getResponseType());
            LOG.debug("ocsp response status: " + resp.getResponseStatus().getValue()); // 0 is ok
            
            //
            
            LOG.debug("=====");
            LOG.debug("signature cert ids: " + s.countCertIDs());
            
            for (int j = 0; j < s.countCertIDs(); j++) {
                CertID cid = s.getCertID(j);
                LOG.debug("===");
                LOG.debug("signature certid id: " + cid.getId());
                LOG.debug("signature certid type: " + cid.getType());
                LOG.debug("signature certid issuer: " + cid.getIssuer());
                LOG.debug("signature certid digestAlgorithm: " + cid.getDigestAlgorithm());
                LOG.debug("signature certid digestValue: " + ConvertUtils.bin2hex(cid.getDigestValue()));
                LOG.debug("signature certid serial: " + cid.getSerial());
            }

            LOG.debug("=====");
            LOG.debug("signature cert values: " + s.countCertValues());
            
            for (int j = 0; j < s.countCertValues(); j++) {
                CertValue cv = s.getCertValue(j);
                LOG.debug("===");
                LOG.debug("cert value id: " + cv.getId());
                LOG.debug("cert value type: " + cv.getType());
                LOG.debug("cert value cert: " + cv.getCert().getSubjectDN());
            }
            
            LOG.debug("=====");
            LOG.debug("signature timestamp infos: " + s.countTimestampInfos());
            
            for (int j = 0; j < s.countTimestampInfos(); j++) {
                TimestampInfo ts = s.getTimestampInfo(j);
                
                LOG.debug("signature timestamp id: " + ts.getId());
                
            }
        }
    }
    
    @Test
    public void testVerifyDigiDocSigneDoc() throws Exception {
        ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext("/ee/sk/digidoc/applicationContext.xml");
        DigiDocService dds = ctx.getBean(DigiDocService.class);
        TrustService trustService = ctx.getBean(TrustService.class);
        NotaryService notaryService = ctx.getBean(NotaryService.class);
        CanonicalizationService canonicalizationService = ctx.getBean(CanonicalizationService.class);
        VerificationServiceImpl verService = new VerificationServiceImpl(trustService, notaryService,
                        canonicalizationService);
        
        SignedDoc sd = dds.readSignedDoc("src/test/data/volikiri.ddoc");
        
        assertNotNull(sd);
        
        List<DigiDocException> errs = verService.verify(sd, true, true);
        
        assertTrue(errs.isEmpty());
        
    }
}
