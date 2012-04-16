package ee.sk.digidoc;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.InputStream;

import org.junit.Test;

public class CreateDDOCContainerTests {

    @Test
    public void createDDOCFile() throws Exception {
        SignedDoc sd = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
        sd.addDataFile(new File("src/test/resources/log4j.properties"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64);
        sd.writeToFile(new File("target/test.ddoc"));
    }

    @Test
    public void createDDOCFileFromStream() throws Exception {
        SignedDoc sd = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
        DataFile df = new DataFile("D0", DataFile.CONTENT_EMBEDDED_BASE64, "log4j", "text/plain", sd);

        InputStream is = this.getClass().getClassLoader().getResourceAsStream("log4j.properties");
        assertNotNull(is);
        df.setBodyFromStream(is);

        sd.addDataFile(df);
        sd.writeToFile(new File("target/test.ddoc"));
    }

    @Test
    public void createBDOCFileFromStream() throws Exception {
        SignedDoc sd = new SignedDoc(SignedDoc.FORMAT_BDOC, SignedDoc.BDOC_VERSION_1_0);
        DataFile df = new DataFile("D0", DataFile.CONTENT_EMBEDDED, "log4j", "text/plain", sd);

        InputStream is = this.getClass().getClassLoader().getResourceAsStream("log4j.properties");
        assertNotNull(is);
        df.setBodyFromStream(is);

        sd.addDataFile(df);
        sd.writeToFile(new File("target/test.bdoc"));
    }
}
