package ee.sk.digidoc.services;

import java.io.InputStream;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.SignedDoc;

public interface DigiDocService {
    
    /**
     * Reads in a DigiDoc or BDOC file
     * 
     * @param fileName file name
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fileName) throws DigiDocException;
    
    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * 
     * @param digiDocStream opened stream with DigiDoc/BDOC data
     *            The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocFromStream(InputStream digiDocStream) throws DigiDocException;
    
    /**
     * Reads in only one <Signature>
     * 
     * @param sdoc SignedDoc to add this signature to
     * @param sigStream opened stream with Signature data
     *            The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public Signature readSignature(SignedDoc sdoc, InputStream sigStream) throws DigiDocException;
}
