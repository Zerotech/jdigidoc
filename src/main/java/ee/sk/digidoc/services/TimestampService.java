package ee.sk.digidoc.services;

import java.security.cert.X509Certificate;
import java.util.List;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.TimestampInfo;

public interface TimestampService {

    boolean verifyTimestamp(TimestampInfo ts, X509Certificate tsaCert) throws DigiDocException;
    
    List<DigiDocException> verifySignaturesTimestamps(Signature sig);
    
}
