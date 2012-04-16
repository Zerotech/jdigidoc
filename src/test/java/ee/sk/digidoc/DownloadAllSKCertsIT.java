package ee.sk.digidoc;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class DownloadAllSKCertsIT {
    
    private static final Logger LOG = Logger.getLogger(DownloadAllSKCertsIT.class);
    
    @Test
    public void downloadAllSKProvidedCertsOnPublicPage() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setValidating(false);
        dbf.setFeature("http://xml.org/sax/features/namespaces", false);
        dbf.setFeature("http://xml.org/sax/features/validation", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        String page = "http://www.sk.ee/repositoorium/sk-sertifikaadid/";
                
        Document doc = dbf.newDocumentBuilder().parse(page);
        XPathExpression ex = XPathFactory.newInstance().newXPath().compile("//a[.='PEM']");

        NodeList ret = (NodeList) ex.evaluate(doc, XPathConstants.NODESET);

        for (int i = 0; i < ret.getLength(); i++) {
            Node node = ret.item(i);
            NamedNodeMap nnm = node.getAttributes();
            Node atr = nnm.getNamedItem("href");
            downloadAndSave(page, atr.getNodeValue().replace(" ","%20"), "src/main/resources/ee/sk/digidoc/certs/");
        }
    }
    
    private void downloadAndSave(String baseurl, String relativeUrl, String localdir) {
        try {
            URL pemUrl = new URL(new URL(baseurl), relativeUrl);
            String filename = localdir + URLDecoder.decode(pemUrl.toString().substring(pemUrl.toString().lastIndexOf('/') + 1),
                    "UTF-8");
            LOG.info("Downloading from " + pemUrl + " to " + filename);
            
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filename));
            BufferedInputStream in = new BufferedInputStream(pemUrl.openStream());
            byte data[] = new byte[1024];

            int read;
            do {
              read = in.read(data, 0, data.length);
              if (read>0) {
                bos.write(data, 0, read);
              }
            } while (read>=0);
            
            in.close();
            bos.flush();
            bos.close();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
}
