package ee.sk.digidoc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.InputStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CreateDDOCContainerTests {
    
    private SignedDoc signedDoc;
    private DataFile dataFile;
    private File targetDDOCFile;
    private File targetBDOCFile;
    
    @Test
    @Before
    public void setUp() throws Exception {
        signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
        dataFile = new DataFile("D0", DataFile.CONTENT_EMBEDDED_BASE64, "log4j", "text/plain", signedDoc);
    }
    
    @Test
    @Before
    public void setTarget() {
        targetBDOCFile =  new File("target/test.bdoc");
        targetDDOCFile =  new File("target/test.ddoc");
        assertFalse(targetDDOCFile.exists());
        assertFalse(targetBDOCFile.exists());

    }

    @After
    public void tearDown() {
        if (targetDDOCFile != null && targetDDOCFile.exists()) {
            targetDDOCFile.delete();
        }
        if (targetBDOCFile != null && targetBDOCFile.exists()) {
            targetBDOCFile.delete();
        }
    }
    
    @Test
    public void createDDOCFile() throws Exception {
        assertFalse(targetDDOCFile.exists());
        
        signedDoc.addDataFile(new File("src/test/resources/log4j.properties"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64);
        signedDoc.writeToFile(targetDDOCFile);
        
        assertTrue(targetDDOCFile.exists());
    }

    @Test
    public void createDDOCFileFromStream() throws Exception {
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("log4j.properties");
        
        assertNotNull(is);
        assertFalse(targetDDOCFile.exists());
        
        dataFile.setBodyFromStream(is);
        signedDoc.addDataFile(dataFile);
        
        signedDoc.writeToFile(targetDDOCFile);
        assertTrue(targetDDOCFile.exists());
    }

    @Test
    public void createBDOCFileFromStream() throws Exception {
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("log4j.properties");
        
        assertNotNull(is);
        assertFalse(targetBDOCFile.exists());
        
        dataFile.setBodyFromStream(is);
        signedDoc.addDataFile(dataFile);
        signedDoc.writeToFile(targetBDOCFile);
        
        assertTrue(targetBDOCFile.exists());
    }
}
