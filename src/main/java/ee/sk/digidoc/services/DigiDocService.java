package ee.sk.digidoc.services;

import java.io.InputStream;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

public interface DigiDocService {
	
	SignedDoc readSignedDoc(String fileName) throws DigiDocException;

	SignedDoc readSignedDoc(InputStream digiDocStream) throws DigiDocException;
}
