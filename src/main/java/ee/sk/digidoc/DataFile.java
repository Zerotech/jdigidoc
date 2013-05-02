/*
 * DataFile.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
 * AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */

package ee.sk.digidoc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.w3c.dom.Node;

import ee.sk.digidoc.services.CanonicalizationService;
import ee.sk.digidoc.services.TinyXMLCanonicalizationServiceImpl;
import ee.sk.utils.Base64InputStream;
import ee.sk.utils.Base64Util;
import ee.sk.utils.ConvertUtils;
import ee.sk.utils.DDUtils;

/**
 * Represents a DataFile instance, that either contains payload data or
 * references and external DataFile.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class DataFile implements Serializable {
    private static final long serialVersionUID = 1L;

    private String contentType;

    private String fileName;

    private String id;

    private String mimeType;

    private long size;
    
    /**
     * digest type of detatched file.
     * digest in xml DataFile attributes.
     */
    private String digestType;
    /** digest value of detatched file */
    private byte[] digestSha1;
    private byte[] digestSha256;
    private byte[] digestSha512;
    /** alternative (sha1) digest if requested */
    private byte[] digestAlternative;
    /**
     * digest value of the XML form of <DataFile>.
     * If read from XML file then calculated immediately otherwise on demand
     */
    private byte[] origDigestValue;

    private List<DataFileAttribute> attributes;
    /** data file contents in original form */
    private byte[] origBody;
    /** initial codepage of DataFile data */
    private String codepage;
    /** parent object reference */
    private SignedDoc sigDoc;

    /** allowed values for content type */
    public static final String CONTENT_EMBEDDED = "EMBEDDED";
    public static final String CONTENT_EMBEDDED_BASE64 = "EMBEDDED_BASE64";
    public static final String CONTENT_BINARY = "BINARY";
    public static final String CONTENT_HASHCODE = "HASHCODE";

    /** the only allowed value for digest type */
    public static final String DIGEST_TYPE_SHA1 = "sha1";
    private static int BLOCK_SIZE = 2048;

    private static final Logger LOG = Logger.getLogger(DataFile.class);
    /** temp file used to cache DataFile data if caching is enabled */
    private transient File m_fDfCache = null;
    
    private boolean m_bodyIsBase64 = false;
    
    private long lMaxDfCached = new Long("4096");

    private final transient CanonicalizationService canonicalizationService = new TinyXMLCanonicalizationServiceImpl();
    
    private boolean useHashcode = false;
    
    private boolean useEmbedded = false;
    
    public void setUseHashcode(boolean useHashcode) {
        this.useHashcode = useHashcode;
    }
    
    public void setUseEmbedded(boolean useEmbedded) {
        this.useEmbedded = useEmbedded;
    }

    /**
     * Creates new DataFile
     * 
     * @param id
     *            id of the DataFile
     * @param contenType
     *            DataFile content type
     * @param fileName
     *            original file name (without path!)
     * @param mimeType
     *            contents mime type
     * @param sdoc
     *            parent object
     * @throws DigiDocException
     *             for validation errors
     */
    public DataFile(String id, String contentType, String fileName, String mimeType, SignedDoc sdoc)
                    throws DigiDocException {
        sigDoc = sdoc;
        codepage = "UTF-8";
        size = 0;
        setId(id);
        setContentType(contentType);
        setFileName(fileName);
        setMimeType(mimeType);
    }

    /**
     * Accessor for temp file object used to cache DataFile data if caching is
     * enabled.
     * 
     * @return temp file object used to cache DataFile data
     */
    public File getDfCacheFile() {
        return m_fDfCache;
    }

    /**
     * Removes temporary DataFile cache file
     */
    public void cleanupDfCache() {
        if (m_fDfCache != null) {
            if (LOG.isDebugEnabled()) LOG.debug("Removing cache file for df: " + m_fDfCache.getAbsolutePath());
            m_fDfCache.delete();
        }
        m_fDfCache = null;
    }

    /**
     * Accessor for body attribute. Note that the body is normally NOT LOADED
     * from file and this attribute is empty!
     * 
     * @return value of body attribute
     */
    public byte[] getBody() throws DigiDocException {
        if (m_fDfCache != null) {
            try {
                byte[] data = DataFile.readFile(m_fDfCache);
                
                if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    data = Base64Util.decode(data);
                }
                
                return data;
            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        }
        return origBody;
    }

    /**
     * Mutator for body attribute. For any bigger files don't use this method!
     * If you are using very small messages onthe other hand then this might
     * speed things up. This method should not be publicly used to assign data
     * to body. If you do then you must also set the initial codepage and size
     * of body!
     * 
     * @param data
     *            new value for body attribute
     */
    public void setBody(byte[] data) throws DigiDocException {
        try {
            origBody = data;
            if (data != null) {
                size = data.length;
                storeInTempFile();
            }
        } catch (IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }
    
    public void setBase64Body(byte[] data) {
        if (data != null) {
            size = data.length;
            origBody = Base64Util.encode(data).getBytes();
            m_bodyIsBase64 = true;
        }
    }

    /**
     * Returnes true if body is already converted to base64
     * 
     * @return true if body is already converted to base64
     */
    public boolean getBodyIsBase64() {
        return m_bodyIsBase64;
    }
    
    /**
     * Set flag to indicate that body is already converted to base64
     * 
     * @param b flag to indicate that body is already converted to base64
     */
    public void setBodyIsBase64(boolean b) {
        m_bodyIsBase64 = b;
    }

    /**
     * Sets DataFile contents from an input stream. This method allways uses
     * temporary files to read out the input stream first in order to determine
     * the size of data. Caller can close the stream after invoking this method
     * because data has been copied. Data is not yet converted to base64 (if
     * required) nor is the hash code calculated at this point. Please not that
     * data is stored in original binary format, so getBody() etc. will not
     * deliver correct result until digidoc has been actually written to disk
     * and read in again.
     * 
     * @param is
     *            input stream delivering the data
     */
    public void setBodyFromStream(InputStream is) throws DigiDocException {
        // copy data to temp file
        try {
            File fCacheDir = new File(System.getProperty("java.io.tmpdir"));
            String dfId = new Long(System.currentTimeMillis()).toString();
            m_fDfCache = File.createTempFile(dfId, ".df", fCacheDir);
            FileOutputStream fos = new FileOutputStream(m_fDfCache);
            origBody = null;
            byte[] data = new byte[2048];
            int nRead = 0;
            size = 0;
            do {
                nRead = is.read(data);
                if (nRead > 0) {
                    fos.write(data, 0, nRead);
                    size += nRead;
                }
            } while (nRead > 0);
            fos.close();
            if (LOG.isDebugEnabled())
                LOG.debug("DF: " + id + " size: " + size + " cache-file: " + m_fDfCache.getAbsolutePath());
        } catch (IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }
    
    public boolean isDigestsCalculated() {
        return (digestSha1 != null || origDigestValue != null || digestSha256 != null || digestSha512 != null);
    }
    
    /**
     * Calculate size and digests
     * 
     * @param is data input stream
     */
    public void calcHashes(InputStream is) throws DigiDocException {
        try {
            digestType = null;
            MessageDigest sha1 = MessageDigest.getInstance(DDUtils.SHA1_DIGEST_TYPE);
            MessageDigest sha256 = MessageDigest.getInstance(DDUtils.SHA256_DIGEST_TYPE);
            MessageDigest sha512 = MessageDigest.getInstance(DDUtils.SHA512_DIGEST_TYPE);
            byte[] data = new byte[2048];
            int nRead = 0;
            size = 0;
            do {
                nRead = is.read(data);
                if (nRead > 0) {
                    sha1.update(data, 0, nRead);
                    sha256.update(data, 0, nRead);
                    sha512.update(data, 0, nRead);
                    size += nRead;
                }
            } while (nRead > 0);
            digestSha1 = origDigestValue = sha1.digest();
            digestSha256 = sha256.digest();
            digestSha512 = sha512.digest();
            if (LOG.isDebugEnabled())
                LOG.debug("DF: " + id + " size: " + size + " dig-sha1: " + Base64Util.encode(digestSha1)
                                + " dig-sha256: " + Base64Util.encode(digestSha256) + " dig-sha512: "
                                + Base64Util.encode(digestSha512));
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
    }
    
    /**
     * Calculate data file hash based on digest type and container type
     * 
     * @param digType digest type
     */
    private byte[] calcHashOfType(String digType) throws DigiDocException {
        byte[] dig = null;
        try {
            if (digType == null
                            || (!digType.equals(DDUtils.SHA1_DIGEST_TYPE)
                                            && !digType.equals(DDUtils.SHA256_DIGEST_TYPE) && !digType
                                                .equals(DDUtils.SHA512_DIGEST_TYPE))) {
                throw new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM, "Invalid digest type: " + digType,
                                null);
            }
            if (sigDoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)
                            || sigDoc.getFormat().equals(SignedDoc.FORMAT_DIGIDOC_XML)) {
                return getDigest();
            }
            MessageDigest sha = MessageDigest.getInstance(digType);
            byte[] data = new byte[2048];
            int nRead = 0;
            InputStream is = getBodyAsStream();
            do {
                nRead = is.read(data);
                if (nRead > 0) sha.update(data, 0, nRead);
            } while (nRead > 0);
            dig = sha.digest();
            if (LOG.isDebugEnabled()) LOG.debug("DF: " + id + " digest: " + digType + " = " + Base64Util.encode(dig));
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        return dig;
    }
    
    /**
     * Set datafile cached content or cache file, calculate size and digest
     * 
     * @param is data input stream
     */
    public void setOrCacheBodyAndCalcHashes(InputStream is) throws DigiDocException {
        try {
            m_fDfCache = createCacheFile();
            OutputStream os = null;
            if (m_fDfCache != null)
                os = new FileOutputStream(m_fDfCache);
            else
                os = new ByteArrayOutputStream();
            digestType = null;
            MessageDigest sha1 = MessageDigest.getInstance(DDUtils.SHA1_DIGEST_TYPE);
            MessageDigest sha256 = MessageDigest.getInstance(DDUtils.SHA256_DIGEST_TYPE);
            MessageDigest sha512 = MessageDigest.getInstance(DDUtils.SHA512_DIGEST_TYPE);
            byte[] data = new byte[2048];
            int nRead = 0;
            size = 0;
            do {
                nRead = is.read(data);
                if (nRead > 0) {
                    sha1.update(data, 0, nRead);
                    sha256.update(data, 0, nRead);
                    sha512.update(data, 0, nRead);
                    os.write(data, 0, nRead);
                    size += nRead;
                }
            } while (nRead > 0);
            digestSha1 = origDigestValue = sha1.digest();
            digestSha256 = sha256.digest();
            digestSha512 = sha512.digest();
            if (m_fDfCache == null) origBody = ((ByteArrayOutputStream) os).toByteArray();
            if (LOG.isDebugEnabled())
                LOG.debug("DF: " + id + " size: " + size + " cache: "
                                + ((m_fDfCache != null) ? m_fDfCache.getAbsolutePath() : "MEMORY") + " dig-sha1: "
                                + Base64Util.encode(digestSha1) + " dig-sha256: " + Base64Util.encode(digestSha256)
                                + " dig-sha512: " + Base64Util.encode(digestSha512));
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    /**
     * Accessor for body attribute. Returns the body as a string. Takes in
     * account the initial codepage. usable only for EMBEDDED type of documents
     * or if body is stored in Base64 then you have to be sure that the
     * converted data is textual and can be returned as a String after decoding.
     * 
     * @return body as string
     */
    public String getBodyAsString() throws DigiDocException {
        String str = null;
        
        if (m_fDfCache != null) {
            try {
                byte[] data = DataFile.readFile(m_fDfCache);

                if (contentType.equals(CONTENT_EMBEDDED)) {
                    str = ConvertUtils.data2str(data, codepage);
                }

                if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    str = ConvertUtils.data2str(Base64Util.decode(data), codepage);
                }

            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        } else {
            if (contentType.equals(CONTENT_EMBEDDED)) {
                str = ConvertUtils.data2str(origBody, codepage);
            }

            if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                str = ConvertUtils.data2str(Base64Util.decode(origBody), codepage);
            }
        }

        return str;
    }

    /**
     * Accessor for body attribute. Returns the body as a byte array. If body
     * contains embedded base64 data then this is decoded first and decoded
     * actual payload data returned.
     * 
     * @return body as a byte array
     */
    public byte[] getBodyAsData() throws DigiDocException {
        byte[] data = null;
        if (m_fDfCache != null) {
            try {
                data = DataFile.readFile(m_fDfCache);

                if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    data = Base64Util.decode(data);
                }
            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        } else {
            if (contentType.equals(CONTENT_EMBEDDED)) {
                data = origBody;
            }

            if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                data = Base64Util.decode(origBody);
            }
        }
        
        return data;
    }
    
    public boolean hasAccessToDataFile() {
        if (m_fDfCache != null || origBody != null) return true;
        File fT = new File(fileName);
        return fT.isFile() && fT.canRead();
    }

    /**
     * Accessor for body attribute.
     * Returns the body as an input stream. If body contains
     * embedded base64 data then this is decoded first
     * and decoded actual payload data returned.
     * 
     * @return body as a byte array
     */
    public InputStream getBodyAsStream() throws DigiDocException {
        InputStream strm = null;
        if (LOG.isDebugEnabled())
            LOG.debug("get body as stream f-cache: " + ((m_fDfCache != null) ? m_fDfCache.getAbsolutePath() : "NULL")
                            + " file: " + ((fileName != null) ? fileName : "NULL") + " content: " + contentType);
        if (m_fDfCache != null || fileName != null) {
            try {
                if (contentType.equals(CONTENT_EMBEDDED)) {
                    strm = new FileInputStream(m_fDfCache);
                }
                if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    if (m_fDfCache != null)
                        strm = new Base64InputStream(new FileInputStream(m_fDfCache));
                    else if (origBody != null) strm = new Base64InputStream(new ByteArrayInputStream(origBody));
                }
                if (contentType.equals(CONTENT_BINARY)) {
                    if (m_fDfCache != null)
                        strm = new FileInputStream(m_fDfCache);
                    else if (origBody != null)
                        strm = new ByteArrayInputStream(origBody);
                    else if (fileName != null) strm = new FileInputStream(fileName);
                }
            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
            }
        } else if (origBody != null) {

        }
        return strm;
    }

    /**
     * Checks if this DataFile object schould use a temp file to store it's data
     * because of memory cache size limitation
     * 
     * @return true if this object schould use temp file
     */
    public boolean schouldUseTempFile() {
        return (size == 0 || (size > lMaxDfCached && (contentType == null)));
    }

    /**
     * Helper method to enable temporary cache file for this DataFile
     * 
     * @return new temporary file object
     * @throws IOException
     */
    public File createCacheFile() throws IOException {
        if ((m_fDfCache == null) && schouldUseTempFile()) {
            File fCacheDir = new File(System.getProperty("java.io.tmpdir"));
            String dfId = new Long(System.currentTimeMillis()).toString();
            m_fDfCache = File.createTempFile(dfId, ".df", fCacheDir);
        }
        return m_fDfCache;
    }
    
    public void setCacheFile(File d) {
        m_fDfCache = d;
    }

    /**
     * Helper method to store body in file if it exceeds the memory cache limit
     * 
     * @throws IOException
     */
    private void storeInTempFile() throws IOException {
        File f = createCacheFile();
        if (f != null) {
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(origBody);
            fos.close();
            // remove memory cache if stored in file
            origBody = null;
        }
    }

    /**
     * Use this method to assign data directly to body. If you do this then the
     * input file will not be read. This also sets the initial size and codepage
     * for you
     * 
     * @param data
     *            new value for body attribute
     */
    public void setBody(byte[] data, String cp) throws DigiDocException {
        try {
            origBody = data;
            codepage = cp;
            size = origBody.length;
            // check if data must be stored in file instead
            storeInTempFile();
        } catch (IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    /**
     * Use this method to assign data directly to body. Input data is an XML
     * subtree
     * 
     * @param xml
     *            xml subtree containing input data
     * @param codepage
     *            input data's original codepage
     */
    public void setBody(Node xml) throws DigiDocException {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            TransformerFactory tFactory = TransformerFactory.newInstance();
            Transformer transformer = tFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            DOMSource source = new DOMSource(xml);
            StreamResult result = new StreamResult(bos);
            transformer.transform(source, result);
            origBody = bos.toByteArray();
            // DOM library always outputs in UTF-8
            codepage = "UTF-8";
            size = origBody.length;
            // check if data must be stored in file instead
            storeInTempFile();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
    }

    public String getCodepage() {
        return codepage;
    }

    /**
     * Mutator for initialCodepage attribute. If you use setBody() or assign
     * data from a file which is not in UTF-8 and then use CONTENT_EMBEDDED then
     * you must use this method to tell the library in which codepage your data
     * is so that we can convert it to UTF-8.
     * 
     * @param data
     *            new value for initialCodepage attribute
     */
    public void setCodepage(String data) {
        codepage = data;
    }

    /**
     * Accessor for contentType attribute
     * 
     * @return value of contentType attribute
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Mutator for contentType attribute
     * 
     * @param str
     *            new value for contentType attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setContentType(String str) throws DigiDocException {
        DigiDocException ex = validateContentType(str);
        if (ex != null) {
            throw ex;
        }

        contentType = str;
    }

    /**
     * Helper method to validate a content type
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateContentType(String str) {
        DigiDocException ex = null;

        if (sigDoc != null && sigDoc.getFormat().equals(SignedDoc.FORMAT_BDOC)
                        && (str == null || !str.equals(CONTENT_BINARY))) {
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_CONTENT_TYPE,
                            "Currently supports only content type BINARY for BDOC format", null);
        }
        if (sigDoc != null
                        && !sigDoc.getFormat().equals(SignedDoc.FORMAT_BDOC)
                        && (str == null
                                        || (!str.equals(CONTENT_EMBEDDED) && !str.equals(CONTENT_EMBEDDED_BASE64) && !str
                                                        .equals(CONTENT_HASHCODE))
                                        || (str.equals(CONTENT_EMBEDDED) && !useEmbedded) || (str
                                        .equals(CONTENT_HASHCODE) && !useHashcode)))
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_CONTENT_TYPE,
                            "Currently supports only content types EMBEDDED_BASE64 for DDOC format", null);

        return ex;
    }

    /**
     * Accessor for fileName attribute
     * 
     * @return value of fileName attribute
     */
    public String getFileName() {
        return fileName;
    }

    /**
     * Mutator for fileName attribute
     * 
     * @param str
     *            new value for fileName attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setFileName(String str) throws DigiDocException {
        DigiDocException ex = validateFileName(str);

        if (ex != null) {
            throw ex;
        }

        fileName = str;
    }

    /**
     * Helper method to validate a file name
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateFileName(String str) {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_FILE_NAME, "Filename is a required attribute",
                            null);
        return ex;
    }

    /**
     * Accessor for id attribute
     * 
     * @return value of id attribute
     */
    public String getId() {
        return id;
    }

    /**
     * Mutator for id attribute
     * 
     * @param str
     *            new value for id attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setId(String str) throws DigiDocException {
        DigiDocException ex = validateId(str, false);
        if (ex != null) throw ex;
        id = str;
    }

    /**
     * Helper method to validate an id
     * 
     * @param str input data
     * @param bStrong flag that specifies if Id atribute value is to
     *            be rigorously checked (according to digidoc format) or only
     *            as required by XML-DSIG
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str, boolean bStrong) {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_ID, "Id is a required attribute", null);
        if (str != null && bStrong && sigDoc.getFormat() != null
                        && !sigDoc.getFormat().equalsIgnoreCase(SignedDoc.FORMAT_BDOC)
                        && (str.charAt(0) != 'D' || !Character.isDigit(str.charAt(1))))
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_ID,
                            "Id attribute value has to be in form D<number>", null);
        return ex;
    }

    public String getMimeType() {
        return mimeType;
    }

    /**
     * Mutator for mimeType attribute
     * 
     * @param str
     *            new value for mimeType attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setMimeType(String str) throws DigiDocException {
        DigiDocException ex = validateMimeType(str);
        
        if (ex != null) {
            throw ex;
        }

        mimeType = str;
    }

    /**
     * Helper method to validate a mimeType
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateMimeType(String str) {
        DigiDocException ex = null;
        
        if (str == null) {
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_MIME_TYPE, "MimeType is a required attribute",
                            null);
        }

        return ex;
    }

    /**
     * Accessor for size attribute
     * 
     * @return value of size attribute
     */
    public long getSize() {
        return size;
    }

    /**
     * Mutator for size attribute
     * 
     * @param l
     *            new value for size attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setSize(long l) throws DigiDocException {
        DigiDocException ex = validateSize(l);
        if (ex != null) throw ex;
        size = l;
    }

    /**
     * Helper method to validate a mimeType
     * 
     * @param l input data
     * @return exception or null for ok
     */
    private DigiDocException validateSize(long l) {
        DigiDocException ex = null;
        if (l < 0)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_SIZE, "Size must be greater or equal to zero",
                            null);
        return ex;
    }

    /**
     * Accessor for digestType attribute
     * 
     * @return value of digestType attribute
     */
    public String getDigestType() {
        return digestType;
    }

    /**
     * Mutator for digestType attribute
     * 
     * @param str
     *            new value for digestType attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setDigestType(String str) throws DigiDocException {
        DigiDocException ex = validateDigestType(str);
        if (ex != null) {
            throw ex;
        }

        digestType = str;
    }

    /**
     * Helper method to validate a digestType
     * 
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestType(String str) {
        DigiDocException ex = null;
        if (str != null && !str.equals(DIGEST_TYPE_SHA1) && !str.equals(DDUtils.SHA1_DIGEST_TYPE)
                        && !str.equals(DDUtils.SHA256_DIGEST_TYPE) && !str.equals(DDUtils.SHA512_DIGEST_TYPE))
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_DIGEST_TYPE,
                            "The only supported digest types are sha1, sha256 and sha512", null);
        return ex;
    }
    
    /**
     * Accessor for digestValue attribute
     * 
     * @param desired digest type
     * @return value of digestValue attribute
     */
    public byte[] getDigestValueOfType(String digType) throws DigiDocException {
        if (digType != null) {
            if (digType.equals(DDUtils.SHA1_DIGEST_TYPE) || digType.equals("sha1")) {
                if (digestSha1 == null && origDigestValue == null)
                    digestSha1 = origDigestValue = calcHashOfType(DDUtils.SHA1_DIGEST_TYPE);
                return ((digestSha1 != null) ? digestSha1 : origDigestValue);
            }
            if (digType.equals(DDUtils.SHA256_DIGEST_TYPE)) {
                if (digestSha256 == null) digestSha256 = calcHashOfType(DDUtils.SHA256_DIGEST_TYPE);
                return digestSha256;
            }
            if (digType.equals(DDUtils.SHA512_DIGEST_TYPE)) {
                if (digestSha512 == null) digestSha512 = calcHashOfType(DDUtils.SHA512_DIGEST_TYPE);
                return digestSha512;
            }
        }
        return digestSha1;
    }

    /**
     * Mutator for digestValue attribute
     * 
     * @param data new value for digestValue attribute
     * @throws DigiDocException for validation errors
     */
    public void setDigestValue(byte[] data) throws DigiDocException {
        DigiDocException ex = validateDigestValue(data);
        if (ex != null) {
            throw ex;
        }
        if (data.length == SignedDoc.SHA1_DIGEST_LENGTH) {
            digestSha1 = data;
        }
        if (data.length == SignedDoc.SHA256_DIGEST_LENGTH) {
            digestSha256 = data;
        }
        if (data.length == SignedDoc.SHA512_DIGEST_LENGTH) {
            digestSha512 = data;
        }
    }

    /**
     * Accessor for digest attribute
     * 
     * @return value of digest attribute
     */
    public byte[] getDigest() throws DigiDocException {
        if (origDigestValue == null) {
            calculateFileSizeAndDigest(null);
        }

        return origDigestValue;
    }

    /**
     * Mutator for digest attribute
     * 
     * @param data
     *            new value for digest attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setDigest(byte[] data) throws DigiDocException {
        DigiDocException ex = validateDigestValue(data);

        if (ex != null) {
            throw ex;
        }

        origDigestValue = data;
    }
    
    /**
     * Accessor for alternate digest attribute
     * 
     * @return value of digest attribute
     */
    public byte[] getAltDigest() {
        return digestAlternative;
    }
    
    /**
     * Mutator for alternate digest attribute
     * 
     * @param b new value for alternate digest attribute
     * @throws DigiDocException for validation errors
     */
    public void setAltDigest(byte[] b) {
        digestAlternative = b;
    }

    /**
     * Helper method to validate a digestValue
     * 
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestValue(byte[] data) {
        DigiDocException ex = null;
        if (data != null && data.length != SignedDoc.SHA1_DIGEST_LENGTH
                        && data.length != SignedDoc.SHA256_DIGEST_LENGTH
                        && data.length != SignedDoc.SHA512_DIGEST_LENGTH)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_DIGEST_VALUE,
                            "SHA1 digest value must be 20 bytes and sha256 digest 32 bytes - is: "
                                            + ((data != null) ? data.length : 0), null);
        return ex;
    }

    /**
     * Returns the count of attributes
     * 
     * @return count of attributes
     */
    public int countAttributes() {
        return ((attributes == null) ? 0 : attributes.size());
    }

    /**
     * Adds a new DataFileAttribute object
     * 
     * @param attr
     *            DataFileAttribute object to add
     */
    public void addAttribute(DataFileAttribute attr) {
        if (attributes == null) attributes = new ArrayList<DataFileAttribute>();
        attributes.add(attr);
    }

    /**
     * Returns the desired DataFileAttribute object
     * 
     * @param idx
     *            index of the DataFileAttribute object
     * @return desired DataFileAttribute object
     */
    public DataFileAttribute getAttribute(int idx) {
        return (DataFileAttribute) attributes.get(idx);
    }

    /**
     * Helper method to validate the whole DataFile object
     * 
     * @param bStrong
     *            flag that specifies if Id atribute value is to be rigorously
     *            checked (according to digidoc format) or only as required by
     *            XML-DSIG
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate(boolean bStrong) {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        DigiDocException ex = validateContentType(contentType);
        if (ex != null) errs.add(ex);
        ex = validateFileName(fileName);
        if (ex != null) errs.add(ex);
        ex = validateId(id, bStrong);
        if (ex != null) errs.add(ex);
        ex = validateMimeType(mimeType);
        if (ex != null) errs.add(ex);
        ex = validateSize(size);
        if (ex != null) errs.add(ex);
        for (int i = 0; i < countAttributes(); i++) {
            DataFileAttribute attr = getAttribute(i);
            List<DigiDocException> e = attr.validate();
            if (!e.isEmpty()) errs.addAll(e);
        }
        return errs;
    }

    /**
     * Helper method to canonicalize a piece of xml
     * 
     * @param xml
     *            data to be canonicalized
     * @return canonicalized xml
     */
    private byte[] canonicalizeXml(byte[] data) {
        try {
            return canonicalizationService.canonicalize(data, SignedDoc.CANONICALIZATION_METHOD_20010315);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Helper method for using an optimization for base64 data's conversion and
     * digest calculation. We use data blockwise to conserve memory
     * 
     * @param os
     *            output stream to write data
     * @param digest
     *            existing sha1 digest to be updated
     * @param b64leftover
     *            leftover base64 data from previous block
     * @param b64left
     *            leftover data length
     * @param data
     *            new binary data
     * @param dLen
     *            number of used bytes in data
     * @param bLastBlock
     *            flag last block
     * @return length of leftover bytes from this block
     * @throws DigiDocException
     */
    private int calculateAndWriteBase64Block(OutputStream os, MessageDigest digest, byte[] b64leftover, int b64left,
                    byte[] data, int dLen, boolean bLastBlock) throws DigiDocException {
        byte[] b64input = null;
        int b64Used, nLeft = 0, nInLen = 0;
        StringBuffer b64data = new StringBuffer();

        if (LOG.isDebugEnabled())
            LOG.debug("os: " + ((os != null) ? "Y" : "N") + " b64left: " + b64left + " input: " + dLen + " last: "
                            + (bLastBlock ? "Y" : "N"));
        try {
            // use data from the last block
            if (b64left > 0) {
                if (dLen > 0) {
                    b64input = new byte[dLen + b64left];
                    nInLen = b64input.length;
                    System.arraycopy(b64leftover, 0, b64input, 0, b64left);
                    System.arraycopy(data, 0, b64input, b64left, dLen);
                    if (LOG.isDebugEnabled()) LOG.debug("use left: " + b64left + " from 0 and add " + dLen);
                } else {
                    b64input = b64leftover;
                    nInLen = b64left;
                    if (LOG.isDebugEnabled()) LOG.debug("use left: " + b64left + " with no new data");
                }
            } else {
                b64input = data;
                nInLen = dLen;
                if (LOG.isDebugEnabled()) LOG.debug("use: " + nInLen + " from 0");
            }
            // encode full rows
            b64Used = Base64Util.encodeToBlock(b64input, nInLen, b64data, bLastBlock);
            nLeft = nInLen - b64Used;
            // use the encoded data
            byte[] encdata = b64data.toString().getBytes();
            if (os != null) os.write(encdata);
            digest.update(encdata);
            // now copy not encoded data back to buffer
            if (LOG.isDebugEnabled()) LOG.debug("Leaving: " + nLeft + " of: " + b64input.length);
            if (nLeft > 0) System.arraycopy(b64input, b64input.length - nLeft, b64leftover, 0, nLeft);
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        if (LOG.isDebugEnabled()) LOG.debug("left: " + nLeft + " bytes for the next run");
        return nLeft;
    }

    /**
     * Calculates the DataFiles size and digest
     * Since it calculates the digest of the external file
     * then this is only useful for detatched files
     * 
     * @throws DigiDocException for all errors
     */
    public void calculateFileSizeAndDigest(OutputStream os) throws DigiDocException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("calculateFileSizeAndDigest(" + getId() + ") body: " + ((origBody != null) ? "OK" : "NULL")
                            + " base64: " + m_bodyIsBase64 + " DF cache: "
                            + ((m_fDfCache != null) ? m_fDfCache.getAbsolutePath() : "NULL"));
        }
        if (contentType.equals(CONTENT_BINARY)) {
            byte[] digest = null;
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                String longFileName = fileName;
                fileName = new File(fileName).getName();
                FileInputStream fis = new FileInputStream(longFileName);
                byte[] data = new byte[4096];
                int nRead = 0;
                long lSize = 0;
                while ((nRead = fis.read(data)) > 0) {
                    sha.update(data, 0, nRead);
                    lSize += nRead;
                }
                digest = sha.digest();
                setSize(lSize);
            } catch (Exception ex) {
                LOG.error("Error calculating bdoc digest: " + ex);
            }
            setDigest(digest);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("DataFile: \'" + getId() + "\' length: " + getSize() + " digest: "
                                + Base64Util.encode(digest));
            }
            return;
        }

        MessageDigest sha = null;

        try {
            sha = MessageDigest.getInstance("SHA-1"); // TODO: fix digest type
            // if DataFile's digest has already been initialized
            // and body in memory, e.g. has been read from digidoc
            // then write directly to output stream and don't calculate again
            if (origDigestValue != null && origBody != null && os != null) {
                os.write(writeXMLHeader());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("write df header1: " + writeXMLHeader());
                }
                os.write(origBody);
                os.write(writeXMLTrailer());
                return;
            }
            String longFileName = fileName;
            File fIn = new File(fileName);
            FileInputStream fis = null;
            fileName = fIn.getName();
            if (fIn.canRead()) {
                fis = new FileInputStream(longFileName);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Read file: " + longFileName);
                }
            }
            if (m_fDfCache != null) {
                fis = new FileInputStream(m_fDfCache);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Read cache: " + m_fDfCache);
                }
            }
            byte[] tmp1 = null, tmp2 = null, tmp3 = null;
            ByteArrayOutputStream sbDig = new ByteArrayOutputStream();
            sbDig.write(writeXMLHeader());
            // add trailer and canonicalize
            tmp3 = writeXMLTrailer();
            sbDig.write(tmp3);
            tmp1 = canonicalizeXml(sbDig.toByteArray());
            // now remove the end tag again and calculate digest of the start tag only
            tmp2 = new byte[tmp1.length - tmp3.length];
            System.arraycopy(tmp1, 0, tmp2, 0, tmp2.length);
            sha.update(tmp2);
            if (os != null) {
                os.write(writeXMLHeader());
            }
            // reset the collecting buffer and other temp buffers
            sbDig = new ByteArrayOutputStream();
            tmp1 = tmp2 = tmp3 = null;
            // content must be read from file
            if (origBody == null) {
                byte[] buf = new byte[BLOCK_SIZE];
                byte[] b64leftover = null;
                int fRead = 0, b64left = 0;
                ByteArrayOutputStream content = null;
                if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    // optimization for 64 char base64 lines
                    // convert to base64 online at a time to conserve memory
                    if (m_fDfCache == null) {
                        b64leftover = new byte[65];
                    }
                }
                while ((fRead = fis.read(buf)) > 0 || b64left > 0) { // read input file
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("read: " + fRead + " bytes of input data");
                    }
                    if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                        if (m_fDfCache != null) {
                            if (os != null) {
                                os.write(buf, 0, fRead);
                            }
                            sha.update(buf, 0, fRead);
                        } else {
                            b64left = calculateAndWriteBase64Block(os, sha, b64leftover, b64left, buf, fRead,
                                            fRead < BLOCK_SIZE);
                        }
                    } else {
                        if (fRead < buf.length) {
                            tmp2 = new byte[fRead];
                            System.arraycopy(buf, 0, tmp2, 0, fRead);
                            tmp1 = ConvertUtils.data2utf8(tmp2, codepage);
                        } else {
                            tmp1 = ConvertUtils.data2utf8(buf, codepage);
                        }
                        sbDig.write(tmp1);
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("End using block: " + fRead + " in: " + ((fis != null) ? fis.available() : 0));
                    }
                } // end reading input file
                if (contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    content = null;
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("End reading content");
                }
            } else { // content already in memory
                if (origBody != null) {
                    if (contentType.equals(CONTENT_EMBEDDED_BASE64) && !m_bodyIsBase64) {
                        calculateAndWriteBase64Block(os, sha, null, 0, origBody, origBody.length, true);
                        origBody = Base64Util.encode(origBody).getBytes();
                    } else {
                        if (contentType.equals(CONTENT_EMBEDDED_BASE64) && !m_bodyIsBase64) {
                            tmp1 = Base64Util.encode(origBody).getBytes();
                        } else if (contentType.equals(CONTENT_EMBEDDED_BASE64) && m_bodyIsBase64) {
                            tmp1 = ConvertUtils.data2utf8(origBody, codepage);
                        } else {
                            tmp1 = ConvertUtils.data2utf8(origBody, codepage);
                        }
                        sbDig.write(tmp1);
                    }
                }
            }
            tmp1 = null;
            if (fis != null) {
                fis.close();
            }
            // don't need to canonicalize base64 content !
            if (!contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                // canonicalize body
                tmp2 = sbDig.toByteArray();
                if (tmp2 != null && tmp2.length > 0) {
                    if (tmp2[0] == '<') {
                        tmp2 = canonicalizeXml(tmp2);
                    }
                    if (tmp2 != null && tmp2.length > 0) {
                        sha.update(tmp2); // crash
                        if (os != null) {
                            os.write(tmp2);
                        }
                    }
                }
            }
            tmp2 = null;
            sbDig = null;
            // trailer          
            tmp1 = writeXMLTrailer();
            sha.update(tmp1);
            if (os != null) os.write(tmp1);
            // now calculate the digest
            byte[] digest = sha.digest();
            setDigest(digest);
            if (LOG.isDebugEnabled()) {
                LOG.debug("DataFile: \'" + getId() + "\' length: " + getSize() + " digest: "
                                + Base64Util.encode(digest));
            }
            fileName = longFileName;
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
    }

    /**
     * Writes the DataFile to an outout file
     * 
     * @param fos
     *            output stream
     * @throws DigiDocException
     *             for all errors
     */
    public void writeToFile(OutputStream fos) throws DigiDocException {
        // for detatched files just read them in
        // calculate digests and store a reference to them
        calculateFileSizeAndDigest(fos);
    }

    /**
     * Helper method to create the xml header
     * 
     * @return xml header
     * @throws DigiDocException
     */
    private byte[] writeXMLHeader() throws DigiDocException {
        StringBuffer sb = new StringBuffer("<DataFile");
        
        if (codepage != null && !codepage.equals("UTF-8")) {
            sb.append(" Codepage=\"");
            sb.append(codepage);
            sb.append("\"");
        }
        
        sb.append(" ContentType=\"");
        sb.append(contentType);
        sb.append("\" Filename=\"");
        // we write only file name not path to file
        String pathLessFileName = new File(fileName).getName();
        if (LOG.isDebugEnabled()) {
            LOG.debug("DF fname: " + ConvertUtils.escapeXmlSymbols(pathLessFileName));
        }
        sb.append(ConvertUtils.escapeXmlSymbols(pathLessFileName));
        sb.append("\" Id=\"");
        sb.append(id);
        sb.append("\" MimeType=\"");
        sb.append(mimeType);
        sb.append("\" Size=\"");
        sb.append(new Long(size).toString());
        sb.append("\"");

        if (digestType != null && digestSha1 != null) {
            sb.append(" DigestType=\"");
            sb.append(digestType);
            sb.append("\" DigestValue=\"");
            sb.append(Base64Util.encode(digestSha1, 0));
            sb.append("\"");
        }

        for (int i = 0; i < countAttributes(); i++) {
            DataFileAttribute attr = getAttribute(i);
            sb.append(" ");
            sb.append(attr.toXML());
        }

        // namespace
        if (sigDoc != null && sigDoc.getVersion().equals(SignedDoc.VERSION_1_3)) {
            sb.append(" xmlns=\"");
            sb.append(SignedDoc.XMLNS_DIGIDOC);
            sb.append("\"");
        }
        
        sb.append(">");
        return ConvertUtils.str2data(sb.toString(), "UTF-8");
    }

    /**
     * Helper method to create the xml trailer
     * 
     * @return xml trailer
     * @throws DigiDocException
     */
    private byte[] writeXMLTrailer() throws DigiDocException {
        return ConvertUtils.str2data("</DataFile>", "UTF-8");
    }

    /**
     * Converts the DataFile to XML form
     * 
     * @return XML representation of DataFile
     * @throws DigiDocException
     */
    public byte[] toXML() throws DigiDocException {
        ByteArrayOutputStream sb = new ByteArrayOutputStream();
        try {
            sb.write(writeXMLHeader());
            if (origBody != null) {
                if (contentType.equals(CONTENT_EMBEDDED) || contentType.equals(CONTENT_EMBEDDED_BASE64)) {
                    sb.write(origBody);
                }
            }
            sb.write(writeXMLTrailer());
        } catch (IOException e) {
            DigiDocException.handleException(e, DigiDocException.ERR_ENCODING);
        }
        return sb.toByteArray();
    }

    public String toString() {
        try {
            return new String(toXML(), "UTF-8");
        } catch (Exception e) {
        }
        return null;
    }

    /**
     * Reads in data file
     * 
     * @param inFile
     *            input file
     */
    protected static byte[] readFile(File inFile) throws IOException, FileNotFoundException {
        byte[] data = null;
        FileInputStream is = new FileInputStream(inFile);
        DataInputStream dis = new DataInputStream(is);
        data = new byte[dis.available()];
        dis.readFully(data);
        dis.close();
        is.close();
        return data;
    }

}
