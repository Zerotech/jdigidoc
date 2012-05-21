package ee.sk.digidoc;

import java.io.ByteArrayInputStream;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import ee.sk.digidoc.services.DigiDocService;

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
        for(int i = 0; i < sd.countDataFiles(); i++) {
            LOG.debug("===");
            DataFile df = sd.getDataFile(i);
            LOG.debug("id: " + df.getId());
            
            LOG.debug("filename: " + df.getFileName());
            LOG.debug("fullname: " + df.getFullName());
            
            LOG.debug("contentType: " + df.getContentType());
            LOG.debug("mimeType: " + df.getMimeType());
            LOG.debug("size: " + df.getSize());
            
            LOG.debug("digestType: " + df.getDigestType());
            LOG.debug("digestValue: " + df.getDigestValue());
            
            //LOG.debug("body: " + df.getBody());
            
            LOG.debug("initialCodepage: " + df.getCodepage());
            
            LOG.debug("datafile attributes: " + df.countAttributes());
            
            for(int j = 0; j < df.countAttributes(); j++) {
                DataFileAttribute dfa = df.getAttribute(j);
                LOG.debug("==");
                LOG.debug("datafile attribute name: " + dfa.getName());
                LOG.debug("datafile attribute value: " + dfa.getValue());
            }
        }
        
        LOG.debug("=============================");
        LOG.debug("no of signaturs: " + sd.countSignatures());
        
        for(int i = 0; i < sd.countSignatures(); i++) {
            Signature s = sd.getSignature(i);
            
            for(int j = 0; j < s.getSignedInfo().countReferences(); j++) {
                Reference r = s.getSignedInfo().getReference(j);
                LOG.debug("==");
                LOG.debug("reference uri: " + r.getUri());
                LOG.debug("reference type: " + r.getType());
                LOG.debug("reference digest algorithm: " + r.getDigestAlgorithm());
                LOG.debug("reference digest value: " + toHex(r.getDigestValue()));
                LOG.debug("reference transform algorithm: " + r.getTransformAlgorithm());
                LOG.debug("reference ref to datafile: " + r.getDataFile());                
            }
            
            LOG.debug("===");
            LOG.debug("signature id: " + s.getId());
            LOG.debug("signedinfo signature method: " + s.getSignedInfo().getSignatureMethod());
            LOG.debug("signedinfo canonicalization method: " + s.getSignedInfo().getCanonicalizationMethod());
            LOG.debug("signedinfo original digest: " + toHex(s.getSignedInfo().getOrigDigest()));
            LOG.debug("signedinfo references count: " + s.getSignedInfo().countReferences());
            
            LOG.debug("==");
            LOG.debug("signaturevalue id: " + s.getSignatureValue().getId());
            LOG.debug("signaturevalue value: " + toHex(s.getSignatureValue().getValue()));
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
            LOG.debug("signature signed properties cert digest algorithm: " + s.getSignedProperties().getCertDigestAlgorithm());
            LOG.debug("signature signed properties cert id: " + s.getSignedProperties().getCertId());
            LOG.debug("signature signed properties cert digest value: " + toHex(s.getSignedProperties().getCertDigestValue()));
            LOG.debug("signature signed properties cert serial: " + s.getSignedProperties().getCertSerial());
            LOG.debug("signature signed properties place city: " + s.getSignedProperties().getSignatureProductionPlace().getCity());
            LOG.debug("signature signed properties place state: " + s.getSignedProperties().getSignatureProductionPlace().getStateOrProvince());
            LOG.debug("signature signed properties place country: " + s.getSignedProperties().getSignatureProductionPlace().getCountryName());
            LOG.debug("signature signed properties place zip: " + s.getSignedProperties().getSignatureProductionPlace().getPostalCode());
            LOG.debug("signature signed properties claimed roles no: " + s.getSignedProperties().countClaimedRoles());
            
            for (int j = 0; j < s.getSignedProperties().countClaimedRoles(); j++) {
                LOG.debug("signature signed properties claimed role: " + s.getSignedProperties().getClaimedRole(j));
            }
            
            LOG.debug("signature signed properties Original digest: " + toHex(s.getSignedProperties().getOrigDigest()));
            LOG.debug("signature signed properties signed data object properties: " + s.getSignedProperties().getSignedDataObjectProperties());
            LOG.debug("signature signed properties data object format: " + s.getSignedProperties().getDataObjectFormat());
            LOG.debug("==");
            
            LOG.debug("signature qualifying properties: " + s.getQualifyingProperties());
            LOG.debug("==");
            LOG.debug("signature unsigned properties complete revocation refs uri: " + s.getUnsignedProperties().getCompleteRevocationRefs().getUri());
            LOG.debug("signature unsigned properties complete revocation refs responderId: " + s.getUnsignedProperties().getCompleteRevocationRefs().getResponderId());
            LOG.debug("signature unsigned properties complete revocation refs produced at: " + s.getUnsignedProperties().getCompleteRevocationRefs().getProducedAt());
            LOG.debug("signature unsigned properties complete revocation refs digest algorithm: " + s.getUnsignedProperties().getCompleteRevocationRefs().getDigestAlgorithm());
            LOG.debug("signature unsigned properties complete revocation refs digest value: " + toHex(s.getUnsignedProperties().getCompleteRevocationRefs().getDigestValue()));
            
            LOG.debug("signature unsigned properties notary id: " + s.getUnsignedProperties().getNotary().getId());
            LOG.debug("signature unsigned properties notary certnr: " + s.getUnsignedProperties().getNotary().getCertNr());
            LOG.debug("signature unsigned properties notary responderid: " + s.getUnsignedProperties().getNotary().getResponderId());
            LOG.debug("signature unsigned properties notary produced at: " + s.getUnsignedProperties().getNotary().getProducedAt());
            LOG.debug("signature unsigned properties notary ocsp reponse data: " + toHex(s.getUnsignedProperties().getNotary().getOcspResponseData()));

            
            
            //
            byte[] ocspdata = s.getUnsignedProperties().getNotary().getOcspResponseData();
            
            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(ocspdata));
            OCSPResponse    resp = OCSPResponse.getInstance(aIn.readObject());
            ResponseBytes   rBytes = ResponseBytes.getInstance(resp.getResponseBytes());
            LOG.debug("ocsp response: " + rBytes.getResponse());
            LOG.debug("ocsp response type: " + rBytes.getResponseType());
            LOG.debug("ocsp response status: " + resp.getResponseStatus().getValue()); // 0 is ok
            
            //
            
            
            
            LOG.debug("=====");
            LOG.debug("signature cert ids: " + s.countCertIDs());
            
            for(int j = 0; j < s.countCertIDs(); j++) {
                CertID cid = s.getCertID(j);
                LOG.debug("===");
                LOG.debug("signature certid id: " + cid.getId());
                LOG.debug("signature certid type: " + cid.getType());
                LOG.debug("signature certid issuer: " + cid.getIssuer());
                LOG.debug("signature certid digestAlgorithm: " + cid.getDigestAlgorithm());
                LOG.debug("signature certid digestValue: " + toHex(cid.getDigestValue()));
                LOG.debug("signature certid serial: " + cid.getSerial());
            }

            LOG.debug("=====");
            LOG.debug("signature cert values: " + s.countCertValues());
            
            for(int j = 0; j < s.countCertValues(); j++) {
                CertValue cv = s.getCertValue(j);
                LOG.debug("===");
                LOG.debug("cert value id: " + cv.getId());
                LOG.debug("cert value type: " + cv.getType());
                LOG.debug("cert value cert: " + cv.getCert().getSubjectDN());
            }
            
            LOG.debug("=====");
            LOG.debug("signature timestamp infos: " + s.countTimestampInfos());

            for(int j = 0; j < s.countTimestampInfos(); j++) {
                TimestampInfo ts = s.getTimestampInfo(j);
                
                LOG.debug("signature timestamp id: " + ts.getId());
                
            }
        }
    }
    
    private String toHex(byte[] in) {
        if (in == null || in.length == 0) {
            return "(0 bytes)";
        }
        
        StringBuffer ret = new StringBuffer();
        ret.append("(" + in.length + " bytes) ");
        
        for(int i = 0; i < in.length; i++) {
            String s = Integer.toHexString(0xFF & in[i]);
            
            if (s.length() == 1) {
                ret.append('0');
            }
            
            ret.append(s);
            ret.append(' ');
        }
        
        return ret.toString();
    }
    
    
}
