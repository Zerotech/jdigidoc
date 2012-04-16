package ee.sk.digidoc;

import java.io.File;

import org.junit.Test;

public class CreateDDOCContainerTests {

    @Test
    public void createDDOCFile() throws Exception {
        SignedDoc sd = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_4);
        sd.addDataFile(new File("src/test/resources/log4j.properties"), "application/octet-stream", DataFile.CONTENT_EMBEDDED_BASE64);
        sd.writeToFile(new File("target/test.ddoc"));
    }
}
