package ee.sk.digidoc;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import ee.sk.utils.Base64Util;

public class CreateDDOCContainerTest {

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

    @Test
    public void createDDOCV1_0_SK_XML_Container() throws Exception {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_SK_XML, SignedDoc.VERSION_1_0);
        signedDoc.addDataFile(new File("pom.xml"), "text/xml", DataFile.CONTENT_EMBEDDED); // misc available file
        signedDoc.addDataFile(new File("README.txt"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64); // misc available file
        signedDoc.addDataFile(new File("LICENSE.txt"), "text/plain", DataFile.CONTENT_DETATCHED); // misc available file
        signedDoc.writeToFile(new File("target/testfile_sk_xml_v1.0.ddoc"));
        signedDoc.toString();
    }

    @Test
    public void createDDOC_DIGIDOC_XML_V1_1_Container() throws Exception {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_1);
        signedDoc.addDataFile(new File("pom.xml"), "text/xml", DataFile.CONTENT_EMBEDDED); // misc available file
        signedDoc.addDataFile(new File("README.txt"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64); // misc available file
        signedDoc.addDataFile(new File("LICENSE.txt"), "text/plain", DataFile.CONTENT_DETATCHED); // misc available file
        signedDoc.writeToFile(new File("target/testfile_digidoc_xml_v1.1.ddoc"));
        signedDoc.toString();
    }

    @Test
    public void createDDOC_DIGIDOC_XML_V1_2_Container() throws Exception {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_2);
        signedDoc.addDataFile(new File("pom.xml"), "text/xml", DataFile.CONTENT_EMBEDDED); // misc available file
        signedDoc.addDataFile(new File("README.txt"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64); // misc available file
        signedDoc.addDataFile(new File("LICENSE.txt"), "text/plain", DataFile.CONTENT_DETATCHED); // misc available file
        signedDoc.writeToFile(new File("target/testfile_digidoc_xml_v1.2.ddoc"));
        signedDoc.toString();
    }

    @Test
    public void createDDOC_DIGIDOC_XML_V1_3_Container() throws Exception {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
        signedDoc.addDataFile(new File("pom.xml"), "text/xml", DataFile.CONTENT_EMBEDDED); // misc available file
        signedDoc.addDataFile(new File("README.txt"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64); // misc available file
        signedDoc.addDataFile(new File("LICENSE.txt"), "text/plain", DataFile.CONTENT_DETATCHED); // misc available file
        signedDoc.writeToFile(new File("target/testfile_digidoc_xml_v1.3.ddoc"));
        signedDoc.toString();
    }

    @Test
    public void createDDOC_DIGIDOC_XML_V1_4_Container() throws Exception {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_4);
        signedDoc.addDataFile(new File("pom.xml"), "text/xml", DataFile.CONTENT_EMBEDDED); // misc available file
        signedDoc.addDataFile(new File("README.txt"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64); // misc available file
        signedDoc.addDataFile(new File("LICENSE.txt"), "text/plain", DataFile.CONTENT_DETATCHED); // misc available file
        signedDoc.writeToFile(new File("target/testfile_digidoc_xml_v1.4.ddoc"));
        signedDoc.toString();
    }

    @Test
    public void create_try_DDOC_DIGIDOC_XML_V1_0_Container() throws Exception {
        try {
            new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_0);
            Assert.fail(); //
        } catch (DigiDocException e) {}
    }

    @Test
    public void create_try_DDOC_SK_XML_V1_1_Container() throws Exception {
        try {
            new SignedDoc(SignedDoc.FORMAT_SK_XML, SignedDoc.VERSION_1_1);
            Assert.fail(); //
        } catch (DigiDocException e) {}
    }

    @Test
    public void createBDOC_V1_0_Container() throws Exception {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_BDOC, SignedDoc.VERSION_1_0);
        signedDoc.addDataFile(new File("pom.xml"), "text/xml", DataFile.CONTENT_EMBEDDED); // misc available file
        // signedDoc.addDataFile(new File("README.txt"), "text/plain", DataFile.CONTENT_EMBEDDED_BASE64); // BDOC supports only EMBEDDED
        // signedDoc.addDataFile(new File("LICENSE.txt"), "text/plain", DataFile.CONTENT_DETATCHED); // BDOC supports only EMBEDDED
        signedDoc.writeToFile(new File("target/testfile_bdoc_v1.0.bdoc"));
        signedDoc.toString();
    }

    @Test
    public void create_try_BDOC_V1_1_Container() throws Exception {
        try {
            new SignedDoc(SignedDoc.FORMAT_BDOC, SignedDoc.VERSION_1_1);
            Assert.fail(); //
        } catch (DigiDocException e) {}
    }

    @Test
    public void createDDOC_DIGIDOC_XML_V1_3_Container_SetBody() throws Exception {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
        DataFile df1 = new DataFile(
                "D0",
                DataFile.CONTENT_EMBEDDED_BASE64,
                "log4j.properties",
                "text/plain",
                signedDoc
                );
        DataFile df2 = new DataFile(
                "D1",
                DataFile.CONTENT_EMBEDDED_BASE64,
                "attachment.pdf",
                "application/pdf",
                signedDoc
                );
        df1.setBody(IOUtils.toByteArray(this.getClass().getClassLoader().getResourceAsStream("log4j.properties")));
        df1.setSize(592L);
        df2.setBody(IOUtils.toByteArray(this.getClass().getClassLoader().getResourceAsStream("attachment.pdf")));
        df2.setSize(9767L);

        signedDoc.addDataFile(df1);
        signedDoc.addDataFile(df2);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        signedDoc.writeToStream(bos);
        String container = bos.toString("utf-8").replace("</DataFile>", "\n</DataFile>");
        System.out.println(container);

        assertFalse(container.contains("Size=\"0\""));

        String base64Line1 = container.substring(container.indexOf("ci5"), container.indexOf("zRq") + 3);
        assertEquals(64, base64Line1.length());
        String base64Line2 = container.substring(container.indexOf("ci9"), container.indexOf("GB6") + 3);
        assertEquals(64, base64Line2.length());

        signedDoc.writeToFile(new File("target/testfile_digidoc_xml_v1.3.ddoc"));
    }
}


