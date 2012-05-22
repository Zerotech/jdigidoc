package ee.sk.digidoc.services;

import ee.sk.digidoc.DigiDocException;

public interface CanonicalizationService {

    /**
     * Canonicalizes XML fragment using the
     * xml-c14n-20010315 algorithm
     * @param data input data
     * @param uri canonicalization algorithm
     * @returns canonicalized XML
     * @throws DigiDocException for all errors
     */
    byte[] canonicalize(byte[] data, String uri);

}
