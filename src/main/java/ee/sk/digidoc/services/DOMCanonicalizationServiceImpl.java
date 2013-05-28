package ee.sk.digidoc.services;

import org.apache.xml.security.c14n.Canonicalizer;

import ee.sk.digidoc.DigiDocException;

public class DOMCanonicalizationServiceImpl implements CanonicalizationService {

    /**
     * Creates new DOMCanonicalizationServiceImpl
     */
    public DOMCanonicalizationServiceImpl() {
        org.apache.xml.security.Init.init();
    }

    /**
     * Canonicalizes XML fragment using the xml-c14n-20010315 algorithm
     * 
     * @param data
     *            input data
     * @param uri
     *            canonicalization algorithm
     * @returns canonicalized XML
     * @throws DigiDocException
     *             for all errors
     */
    public byte[] canonicalize(byte[] data, String uri) throws DigiDocException {
        byte[] result = null;
        try {
            org.apache.xml.security.Init.init();
            Canonicalizer c14n = Canonicalizer.getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            result = c14n.canonicalize(data);
        } catch (Exception e) {
            DigiDocException.handleException(e, DigiDocException.ERR_CAN_ERROR);
        }
        return result;
    }
}
