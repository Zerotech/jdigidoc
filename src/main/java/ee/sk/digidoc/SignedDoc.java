/*
 * SignedDoc.java
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */

package ee.sk.digidoc;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.log4j.Logger;

import ee.sk.digidoc.services.DigiDocGenServiceImpl;
import ee.sk.digidoc.services.DigiDocXmlGenerator;
import ee.sk.utils.DDUtils;

/**
 * Represents an instance of signed doc in DIGIDOC format. Contains one or more
 * DataFile -s and zero or more Signature -s.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class SignedDoc implements Serializable {
    
    private static Logger LOG = Logger.getLogger(SignedDoc.class);

    private String format;

    private String version;

    private List<DataFile> dataFiles;

    private List<Signature> signatures;
    
    private Manifest manifest;
    
    private String mimeType;
    /** xml-dsig namespace preifx */
    private String nsXmlDsig;
    /** xades namespace prefix */
    private String nsXades;
    /** signature default profile */
    private String profile;

    /** hashtable of signature names and formats used during loading */
    private Hashtable<String, String> sigFormats;
    
    private long size;
    /** original container path */
    private String path;
    /** original container filename without path */
    private String file;

    public static final String FORMAT_SK_XML = "SK-XML";
    public static final String FORMAT_DIGIDOC_XML = "DIGIDOC-XML";
    public static final String FORMAT_XADES_T = "XADES-T";
    public static final String FORMAT_XADES = "XADES";

    public static final String FORMAT_BDOC = "BDOC";

    public static final String VERSION_1_0 = "1.0";
    public static final String VERSION_1_1 = "1.1";
    public static final String VERSION_1_2 = "1.2";
    public static final String VERSION_1_3 = "1.3";

    /** bdoc versions are 1.0 and 1.1 */
    public static final String BDOC_VERSION_1_0 = "1.0";
    public static final String BDOC_VERSION_1_1 = "1.1";
    
    /** bdoc profiles are - BES, T, C-L, TM, TS, TM-A, TS-A */
    public static final String BDOC_PROFILE_BES = "BES";
    public static final String BDOC_PROFILE_T = "T";
    public static final String BDOC_PROFILE_CL = "C-L";
    public static final String BDOC_PROFILE_TM = "TM";
    public static final String BDOC_PROFILE_TS = "TS";
    public static final String BDOC_PROFILE_TMA = "TM-A";
    public static final String BDOC_PROFILE_TSA = "TS-A";

    /** the only supported algorithm for ddoc is SHA1 */
    public static final String SHA1_DIGEST_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#sha1";
    /** the only supported algorithm for bdoc is SHA256 */
    public static final String SHA256_DIGEST_ALGORITHM_1 = "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String SHA256_DIGEST_ALGORITHM_2 = "http://www.w3.org/2001/04/xmldsig-more#sha256";
    /** algorithm for sha 224 **/
    public static final String SHA224_DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#sha224";
    /** algorithm for sha-512 */
    public static final String SHA512_DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha512";
    /** SHA1 digest data is always 20 bytes */
    public static final int SHA1_DIGEST_LENGTH = 20;
    /** SHA224 digest data is always 28 bytes */
    public static final int SHA224_DIGEST_LENGTH = 28;
    /** SHA256 digest data is always 32 bytes */
    public static final int SHA256_DIGEST_LENGTH = 32;
    /** SHA512 digest data is always 64 bytes */
    public static final int SHA512_DIGEST_LENGTH = 64;
    /** the only supported canonicalization method is 20010315 */
    public static final String CANONICALIZATION_METHOD_20010315 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public static final String TRANSFORM_20001026 = "http://www.w3.org/TR/2000/CR-xml-c14n-20001026";
    /** signature methods */
    public static final String RSA_SHA1_SIGNATURE_METHOD = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    public static final String RSA_SHA224_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
    public static final String RSA_SHA256_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String RSA_SHA512_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    /** the only supported transform is digidoc detached transform */
    public static final String DIGIDOC_DETATCHED_TRANSFORM = "http://www.sk.ee/2002/10/digidoc#detatched-document-signature";
    public static final String ENVELOPED_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    public static final String SIGNEDPROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

    public static final String XMLNS_XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

    public static final String XMLNS_ETSI = "http://uri.etsi.org/01903/v1.1.1#";

    public static final String XMLNS_DIGIDOC = "http://www.sk.ee/DigiDoc/v1.3.0#";

    public static final String XMLNS_XADES_123 = "http://uri.etsi.org/01903/v1.3.2#";

    public static final String SIG_FILE_NAME = "META-INF/signature";
    public static final String MIMET_FILE_NAME = "mimetype";
    public static final String MIMET_FILE_CONTENT_10 = "application/vnd.bdoc-1.0";
    public static final String MIMET_FILE_CONTENT_11 = "application/vnd.bdoc-1.1";
    public static final String MANIF_DIR_META_INF = "META-INF";
    public static final String MANIF_FILE_NAME = "META-INF/manifest.xml";
    public static final String MIME_SIGNATURE_BDOC_ = "signature/bdoc-";
    
    public SignedDoc() {}

    /**
     * Creates new SignedDoc
     * 
     * @param format
     *            file format name
     * @param version
     *            file version number
     * @throws DigiDocException
     *             for validation errors
     */
    public SignedDoc(String format, String version) throws DigiDocException {
        setFormatAndVersion(format, version);
        if (format.equals(SignedDoc.FORMAT_BDOC)) {
            manifest = new Manifest();
            ManifestFileEntry fe = new ManifestFileEntry(
                            version.equals(BDOC_VERSION_1_0) ? Manifest.MANIFEST_BDOC_MIME_1_0
                                            : Manifest.MANIFEST_BDOC_MIME_1_1, "/");
            manifest.addFileEntry(fe);
            nsXmlDsig = "ds";
            nsXades = "xades";
        }
        if (format.equals(SignedDoc.FORMAT_XADES)) {
            nsXmlDsig = "ds";
            nsXades = "xades";
        }
    }
    
    /**
     * Finds Manifest file-netry by path
     * 
     * @param fullPath file path in bdoc
     * @return file-netry if found
     */
    public ManifestFileEntry findManifestEntryByPath(String fullPath) {
        return manifest.findFileEntryByPath(fullPath);
    }

    public String getFormat() {
        return format;
    }

    /**
     * Mutator for format attribute
     * 
     * @param str
     *            new value for format attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setFormat(String str) throws DigiDocException {
        DigiDocException ex = validateFormat(str);
        if (ex != null) {
            throw ex;
        }

        format = str.toUpperCase();
    }

    /**
     * Helper method to validate a format
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    public DigiDocException validateFormat(String str) {
        DigiDocException ex = null;
        if (str == null) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "Format attribute is mandatory!", null);
        } else {
            if (!str.equals(FORMAT_XADES_T) && !str.equals(FORMAT_XADES) && !str.equals(FORMAT_BDOC)
                            && !str.equals(FORMAT_SK_XML) && !str.equals(FORMAT_DIGIDOC_XML)) {
                ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                                "Currently supports only SK-XML, DIGIDOC-XML and BDOC formats", null);
            }
        }
        return ex;
    }
    
    /**
     * Accessor for all data-files atribute
     * 
     * @return all data-files
     */
    public List<DataFile> getDataFiles() {
        return dataFiles;
    }
    
    /**
     * Accessor for all signatures atribute
     * 
     * @return all signatures
     */
    public List<Signature> getSignatures() {
        return signatures;
    }
    
    /**
     * Accessor for size atribute
     * 
     * @return size in bytes
     */
    public long getSize() {
        return size;
    }
    
    /**
     * Mutator for size atribute
     * 
     * @param size in bytes
     */
    public void setSize(long l) {
        size = l;
    }
    
    /**
     * Accessor for file atribute
     * 
     * @return original container filename without path
     */
    public String getFile() {
        return file;
    }
    
    /**
     * Mutator for file atribute
     * 
     * @param fname original filename without path
     */
    public void setFile(String fname) {
        file = fname;
    }
    
    /**
     * Accessor for path atribute
     * 
     * @return original file path without filename
     */
    public String getPath() {
        return path;
    }
    
    /**
     * Mutator for size atribute
     * 
     * @param p original container path without filename
     */
    public void setPath(String p) {
        path = p;
    }
    
    /**
     * Registers a new signature format
     * 
     * @param sigId signature id
     * @param profile format/profile
     */
    public void addSignatureProfile(String sigId, String profile) {
        if (sigFormats == null) {
            sigFormats = new Hashtable<String, String>();
        }
        if (LOG.isDebugEnabled()) LOG.debug("Register signature: " + sigId + " profile: " + profile);
        sigFormats.put(sigId, profile);
    }
    
    /**
     * Returns signature profile
     * 
     * @param sigId signature id
     * @return profile
     */
    public String findSignatureProfile(String sigId) {
        return ((sigFormats != null) ? (String) sigFormats.get(sigId) : null);
    }
    
    /**
     * Accessor for xml-dsig ns prefix attribute
     * 
     * @return value of xml-dsig ns prefi attribute
     */
    public String getXmlDsigNs() {
        return nsXmlDsig;
    }
    
    /**
     * Mutator for xml-dsig ns prefi attribute
     * 
     * @param str new value for xml-dsig ns prefi attribute
     */
    public void setXmlDsigNs(String str) {
        nsXmlDsig = str;
    }
    
    /**
     * Accessor for xades ns prefix attribute
     * 
     * @return value of xades ns prefi attribute
     */
    public String getXadesNs() {
        return nsXades;
    }
    
    /**
     * Mutator for xades ns prefi attribute
     * 
     * @param str new value for xades ns prefi attribute
     */
    public void setXadesNs(String str) {
        nsXades = str;
    }
    
    /**
     * Accessor for profile attribute
     * 
     * @return value of profile attribute
     */
    public String getProfile() {
        return profile;
    }
    
    /**
     * Mutator for profile attribute
     * 
     * @param s new value for profile attribute
     */
    public void setProfile(String s) {
        profile = s;
    }

    public String getVersion() {
        return version;
    }

    /**
     * Mutator for version attribute
     * 
     * @param str
     *            new value for version attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setVersion(String str) throws DigiDocException {
        DigiDocException ex = validateVersion(str);
        
        if (ex != null) {
            throw ex;
        }

        version = str;
    }

    /**
     * Helper method to validate a version Lauri Lyys: 2009 oct, fixed the
     * version validation exception message, also supporting ignoreCase on bdoc
     * format
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    public DigiDocException validateVersion(String str) {
        DigiDocException ex = null;
        if (str == null) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "Version attribute is mandatory!", null);
        } else {
            if (format != null) {
                if (format.equals(FORMAT_SK_XML) && !str.equals(VERSION_1_0))
                    ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION,
                                    "Format SK-XML supports only version 1.0", null);
                if (format.equals(FORMAT_DIGIDOC_XML) && !str.equals(VERSION_1_1) && !str.equals(VERSION_1_2)
                                && !str.equals(VERSION_1_3))
                    ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION,
                                    "Format DIGIDOC-XML supports only versions 1.1, 1.2, 1.3", null);
                if (format.equals(FORMAT_BDOC) && !str.equals(VERSION_1_0) && !str.equals(VERSION_1_1))
                    ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION,
                                    "Format BDOC supports only versions 1.0 and 1.1", null);
            }
        }
        return ex;
    }
    
    /**
     * Sets a combination of format and version and validates data
     * 
     * @param sFormat format string
     * @param sVersion version string
     * @throws DigiDocException in case of invalid format/version
     */
    public void setFormatAndVersion(String sFormat, String sVersion) throws DigiDocException {
        format = sFormat;
        version = sVersion;
        DigiDocException ex = validateFormatAndVersion();
        if (ex != null) throw ex;
    }
    
    /**
     * Helper method to validate both format and version
     * 
     * @return exception or null for ok
     */
    public DigiDocException validateFormatAndVersion() {
        if (format == null || version == null) {
            return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                            "Format and version attributes are mandatory!", null);
        }
        if (format.equals(FORMAT_DIGIDOC_XML)) {
            if (!version.equals(VERSION_1_3))
                return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                                "Format DIGIDOC-XML supports only version 1.3", null);
        } else if (format.equals(FORMAT_BDOC)) {
            if (!version.equals(VERSION_1_0) && !version.equals(VERSION_1_1))
                return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                                "Format BDOC supports only versions 1.0 and 1.1", null);
        } else {
            return new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, "Invalid format attribute!", null);
        }
        return null;
    }
    
    /**
     * Accessor for manifest attribute
     * 
     * @return value of manifest attribute
     */
    public Manifest getManifest() {
        return manifest;
    }
    
    /**
     * Mutator for manifest element
     * 
     * @param m manifest element
     */
    public void setManifest(Manifest m) {
        manifest = m;
    }
    
    /**
     * Accessor for mime-type attribute
     * 
     * @return value of mime-type attribute
     */
    public String getMimeType() {
        return mimeType;
    }
    
    /**
     * Mutator for mime-type attribute
     * 
     * @param str new value for mime-type attribute
     */
    public void setMimeType(String str) {
        mimeType = str;
    }

    /**
     * return the count of DataFile objects
     * 
     * @return count of DataFile objects
     */
    public int countDataFiles() {
        return ((dataFiles == null) ? 0 : dataFiles.size());
    }

    /**
     * Removes temporary DataFile cache files
     */
    public void cleanupDfCache() {
        for (int i = 0; (dataFiles != null) && (i < dataFiles.size()); i++) {
            DataFile df = (DataFile) dataFiles.get(i);
            df.cleanupDfCache();
        }
    }
    
    public InputStream findDataFileAsStream(String dfName) {
        try {
            if (file != null) {
                StringBuffer sbName = new StringBuffer();
                if (path != null) {
                    sbName.append(path);
                    sbName.append(File.separator);
                }
                sbName.append(file);
                File fZip = new File(sbName.toString());
                if (fZip.isFile() && fZip.canRead()) {
                    ZipFile zis = new ZipFile(fZip);
                    ZipArchiveEntry ze = zis.getEntry(dfName);
                    if (ze != null) {
                        return zis.getInputStream(ze);
                    }
                }
            }
        } catch (Exception ex) {
            LOG.error("Error reading bdoc: " + ex);
        }
        return null;
    }

    /**
     * return a new available DataFile id
     * 
     * @retusn new DataFile id
     */
    public String getNewDataFileId() {
        int nDf = 0;
        String id = "D" + nDf;
        boolean bExists = false;
        do {
            bExists = false;
            for (int d = 0; d < countDataFiles(); d++) {
                DataFile df = getDataFile(d);
                if (df.getId().equals(id)) {
                    nDf++;
                    id = "D" + nDf;
                    bExists = true;
                    continue;
                }
            }
        } while (bExists);
        return id;
    }

    /**
     * Adds a new DataFile to signed doc
     * 
     * @param inputFile
     *            input file name
     * @param mime
     *            files mime type
     * @param contentType
     *            DataFile's content type
     * @return new DataFile object
     */
    public DataFile addDataFile(File inputFile, String mime, String contentType) throws DigiDocException {
        DigiDocException ex1 = validateFormatAndVersion();
        if (ex1 != null) throw ex1;
        DataFile df = new DataFile(getNewDataFileId(), contentType, inputFile.getAbsolutePath(), mime, this);
        if (inputFile.canRead()) df.setSize(inputFile.length());
        addDataFile(df);
        if (format.equals(SignedDoc.FORMAT_BDOC)) {
            df.setContentType(DataFile.CONTENT_BINARY);
            ManifestFileEntry fe = new ManifestFileEntry(mime, inputFile.getName());
            manifest.addFileEntry(fe);
        }
        if (format.equals(SignedDoc.FORMAT_XADES)) {
            df.setContentType(DataFile.CONTENT_BINARY);
            df.setId("/" + inputFile.getName());
            try {
                byte[] dfData = DataFile.readFile(inputFile);
                byte[] hash = DDUtils.digestOfType(dfData, DDUtils.SHA1_DIGEST_TYPE);
                df.setDigest(hash);
            } catch (Exception ex) {
                
            }
        }
        return df;
    }

    /**
     * Writes the SignedDoc to an output file and automatically calculates
     * DataFile sizes and digests
     * 
     * @param outputFile
     *            output file name
     * @throws DigiDocException
     *             for all errors
     */
    public void writeToFile(File outputFile) throws DigiDocException {
        try {
            FileOutputStream fos = new FileOutputStream(outputFile);
            writeToStream(fos);
            fos.close();
        } catch (DigiDocException ex) {
            throw ex; // allready handled
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
    }

    /**
     * Writes the SignedDoc to an output file and automatically calculates
     * DataFile sizes and digests
     * 
     * @param outputFile
     *            output file name
     * @throws DigiDocException
     *             for all errors
     */
    public void writeToStream(OutputStream os) throws DigiDocException {
        DigiDocException ex1 = validateFormatAndVersion();
        if (ex1 != null) throw ex1;
        try {
            DigiDocXmlGenerator xmlGenerator = new DigiDocXmlGenerator(this);
            if (format.equals(SignedDoc.FORMAT_BDOC)) {
                ZipArchiveOutputStream zos = new ZipArchiveOutputStream(os);
                zos.setEncoding("UTF-8");
                if (LOG.isDebugEnabled())
                    LOG.debug("OS: " + ((os != null) ? "OK" : "NULL") + " zos: " + ((zos != null) ? "OK" : "NULL"));
                // write mimetype
                if (LOG.isDebugEnabled()) LOG.debug("Writing: " + MIMET_FILE_NAME);
                ZipArchiveEntry ze = new ZipArchiveEntry(MIMET_FILE_NAME);
                zos.putArchiveEntry(ze);
                if (version.equals(BDOC_VERSION_1_0)) zos.write(SignedDoc.MIMET_FILE_CONTENT_10.getBytes());
                if (version.equals(BDOC_VERSION_1_1)) zos.write(SignedDoc.MIMET_FILE_CONTENT_11.getBytes());
                zos.closeArchiveEntry();
                // write manifest.xml
                if (LOG.isDebugEnabled()) LOG.debug("Writing: " + MANIF_FILE_NAME);
                ze = new ZipArchiveEntry(MANIF_DIR_META_INF);
                ze = new ZipArchiveEntry(MANIF_FILE_NAME);
                zos.putArchiveEntry(ze);
                zos.write(manifest.toXML());
                zos.closeArchiveEntry();
                // write data files
                for (int i = 0; i < countDataFiles(); i++) {
                    DataFile df = getDataFile(i);
                    if (LOG.isDebugEnabled())
                        LOG.debug("Writing DF: "
                                        + df.getFileName()
                                        + " content: "
                                        + df.getContentType()
                                        + " df-cache: "
                                        + ((df.getDfCacheFile() != null) ? df.getDfCacheFile().getAbsolutePath()
                                                        : "NONE"));
                    InputStream is = null;
                    if (df.hasAccessToDataFile())
                        is = df.getBodyAsStream();
                    else
                        is = findDataFileAsStream(df.getFileName());
                    if (is != null) {
                        File dfFile = new File(df.getFileName());
                        String fileName = dfFile.getName();
                        ze = new ZipArchiveEntry(fileName);
                        ze.setSize(dfFile.length());
                        zos.putArchiveEntry(ze);
                        byte[] data = new byte[2048];
                        int nRead = 0;
                        while ((nRead = is.read(data)) > 0)
                            zos.write(data, 0, nRead);
                        zos.closeArchiveEntry();
                        is.close();
                    }
                }
                for (int i = 0; i < countSignatures(); i++) {
                    Signature sig = getSignature(i);
                    String sFileName = sig.getPath();
                    if (sFileName == null) sFileName = SIG_FILE_NAME + (i + 1) + ".xml";
                    if (!sFileName.startsWith("META-INF")) sFileName = "META-INF/" + sFileName;
                    if (LOG.isDebugEnabled())
                        LOG.debug("Writing SIG: " + sFileName + " orig: "
                                        + ((sig.getOrigContent() != null) ? "OK" : "NULL"));
                    ze = new ZipArchiveEntry(sFileName);
                    String sSig = sig.toString();
                    if (!sSig.startsWith("<?xml")) sSig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + sSig;
                    byte[] sdata = sig.getOrigContent();
                    if (sdata == null) sdata = xmlGenerator.signatureToXML(sig);
                    ze.setSize(sdata.length);
                    zos.putArchiveEntry(ze);
                    zos.write(sdata);
                    zos.closeArchiveEntry();
                }
                zos.close();
            } else if (format.equals(SignedDoc.FORMAT_XADES)) {
                for (int i = 0; i < countSignatures(); i++) {
                    Signature sig = getSignature(i);
                    os.write(xmlGenerator.signatureToXML(sig));
                }
            } else if (format.equals(SignedDoc.FORMAT_DIGIDOC_XML)) { // ddoc format
                os.write(xmlHeader().getBytes());
                for (int i = 0; i < countDataFiles(); i++) {
                    DataFile df = getDataFile(i);
                    df.writeToFile(os);
                    os.write("\n".getBytes());
                }
                for (int i = 0; i < countSignatures(); i++) {
                    Signature sig = getSignature(i);
                    if (sig.getOrigContent() != null)
                        os.write(sig.getOrigContent());
                    else
                        os.write(xmlGenerator.signatureToXML(sig));
                    os.write("\n".getBytes());
                }
                os.write(xmlTrailer().getBytes());
            }
        } catch (DigiDocException ex) {
            throw ex; // allready handled
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    /**
     * Adds a new DataFile object
     * 
     * @param attr
     *            DataFile object to add
     */
    public void addDataFile(DataFile df) throws DigiDocException {
        if (countSignatures() > 0) {
            throw new DigiDocException(DigiDocException.ERR_SIGATURES_EXIST,
                            "Cannot add DataFiles when signatures exist!", null);
        }

        if (dataFiles == null) {
            dataFiles = new ArrayList<DataFile>();
        }

        if (df.getId() == null) {
            df.setId(getNewDataFileId());
        }

        dataFiles.add(df);
    }

    /**
     * return the desired DataFile object
     * 
     * @param idx
     *            index of the DataFile object
     * @return desired DataFile object
     */
    public DataFile getDataFile(int idx) {
        return dataFiles.get(idx);
    }

    /**
     * return the latest DataFile object
     * 
     * @return desired DataFile object
     */
    public DataFile getLastDataFile() {
        return dataFiles.get(dataFiles.size() - 1);
    }

    /**
     * Removes the datafile with the given index
     * 
     * @param idx
     *            index of the data file
     */
    public void removeDataFile(int idx) throws DigiDocException {
        if (countSignatures() > 0) {
            throw new DigiDocException(DigiDocException.ERR_SIGATURES_EXIST,
                            "Cannot remove DataFiles when signatures exist!", null);
        }
        DataFile df = getDataFile(idx);
        if (df != null) {
            dataFiles.remove(idx);
            if (manifest != null) manifest.removeFileEntryWithPath(df.getFileName());
        } else {
            throw new DigiDocException(DigiDocException.ERR_DATA_FILE_ID, "Invalid DataFile index!", null);
        }
    }
    
    /**
     * Returns DataFile with desired id
     * 
     * @param id Id attribute value
     * @return DataFile object or null if not found
     */
    public DataFile findDataFileById(String id) {
        for (int i = 0; (dataFiles != null) && (i < dataFiles.size()); i++) {
            DataFile df = dataFiles.get(i);
            if (df.getId() != null && id != null && df.getId().equals(id)) return df;
        }
        return null;
    }

    /**
     * return the count of Signature objects
     * 
     * @return count of Signature objects
     */
    public int countSignatures() {
        return ((signatures == null) ? 0 : signatures.size());
    }

    /**
     * return a new available Signature id
     * 
     * @return new Signature id
     */
    public String getNewSignatureId() {
        int nS = 0;
        String id = "S" + nS;
        boolean bExists = false;
        do {
            bExists = false;
            for (int i = 0; i < countSignatures(); i++) {
                Signature sig = getSignature(i);
                if (sig.getId().equals(id)) {
                    nS++;
                    id = "S" + nS;
                    bExists = true;
                    continue;
                }
            }
        } while (bExists);
        return id;
    }

    /**
     * Find signature by id atribute value
     * 
     * @param sigId
     *            signature Id atribute value
     * @return signature object or null if not found
     */
    public Signature findSignatureById(String sigId) {
        for (int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            if (sig.getId().equals(sigId)) return sig;
        }
        return null;
    }
    
    /**
     * Find signature by path atribute value
     * 
     * @param path signature path atribute value (path in bdoc container)
     * @return signature object or null if not found
     */
    public Signature findSignatureByPath(String path) {
        for (int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            if (sig.getPath() != null && sig.getPath().equals(path)) return sig;
        }
        return null;
    }

    /**
     * Adds a new uncomplete signature to signed doc
     * 
     * @param cert signers certificate
     * @param claimedRoles signers claimed roles
     * @param adr signers address
     * @return new Signature object
     */
    public Signature prepareSignature(X509Certificate cert, String[] claimedRoles, SignatureProductionPlace adr,
                    DigiDocGenServiceImpl genService) throws DigiDocException {
        DigiDocException ex1 = validateFormatAndVersion();
        if (ex1 != null) throw ex1;
        return genService.prepareXadesBES(this, profile, cert, claimedRoles, adr, null, null, null);
    }
    
    /**
     * Adds a new uncomplete signature to signed doc
     * 
     * @param cert signers certificate
     * @return new Signature object
     */
    public Signature prepareXadesTSignature(X509Certificate cert, String sigDatId, byte[] sigDatHash)
                    throws DigiDocException {
        Signature sig = new Signature(this);
        sig.setId(getNewSignatureId());
        // create SignedInfo block
        SignedInfo si = new SignedInfo(sig, RSA_SHA1_SIGNATURE_METHOD, CANONICALIZATION_METHOD_20010315);
        // add DataFile references
        Reference ref = new Reference(si, "#" + sigDatId, SignedDoc.SHA1_DIGEST_ALGORITHM, sigDatHash,
                        TRANSFORM_20001026);
        si.addReference(ref);
        sig.setSignedInfo(si);
        // create key info
        KeyInfo ki = new KeyInfo(cert);
        sig.setKeyInfo(ki);
        ki.setSignature(sig);
        CertValue cval = new CertValue(null, cert, CertValue.CERTVAL_TYPE_SIGNER, sig);
        sig.addCertValue(cval);
        CertID cid = new CertID(sig, cert, CertID.CERTID_TYPE_SIGNER);
        sig.addCertID(cid);
        addSignature(sig);
        UnsignedProperties usp = new UnsignedProperties(sig, null, null);
        sig.setUnsignedProperties(usp);
        return sig;
    }

    /**
     * Adds a new Signature object
     * 
     * @param attr Signature object to add
     */
    public void addSignature(Signature sig) {
        if (signatures == null) {
            signatures = new ArrayList<Signature>();
        }
        signatures.add(sig);
        if (format != null && format.equals(SignedDoc.FORMAT_BDOC)) {
            Signature sig1 = null;
            if (sig.getPath() != null) sig1 = findSignatureByPath(sig.getPath());
            if (sig1 == null) {
                ManifestFileEntry fe = new ManifestFileEntry(SignedDoc.MIME_SIGNATURE_BDOC_ + version + "/"
                                + sig.getProfile(), SignedDoc.SIG_FILE_NAME + signatures.size() + ".xml");
                sig.setPath(SignedDoc.SIG_FILE_NAME + signatures.size() + ".xml");
                manifest.addFileEntry(fe);
                if (LOG.isDebugEnabled()) LOG.debug("Register in manifest new signature: " + sig.getId());
            }
        }
    }

    /**
     * return the desired Signature object
     * 
     * @param idx
     *            index of the Signature object
     * @return desired Signature object
     */
    public Signature getSignature(int idx) {
        return signatures.get(idx);
    }

    /**
     * Removes the desired Signature object
     * 
     * @param idx
     *            index of the Signature object
     */
    public void removeSignature(int idx) {
        signatures.remove(idx);
    }

    /**
     * return the latest Signature object
     * 
     * @return desired Signature object
     */
    public Signature getLastSignature() {
        if (signatures != null && signatures.size() > 0) {
            return signatures.get(signatures.size() - 1);
        } else {
            return null;
        }
    }
    
    /**
     * Deletes last signature
     */
    public void removeLastSiganture() {
        if (signatures.size() > 0) {
            signatures.remove(signatures.size() - 1);
        }
    }
    
    /**
     * Removes signatures without value. Temporary signatures created
     * during signing process but without completing the process
     */
    public int removeSignaturesWithoutValue() {
        int removed = 0;
        boolean bOk = true;
        do {
            bOk = true;
            for (int i = 0; (signatures != null) && (i < signatures.size()) && bOk; i++) {
                Signature sig = signatures.get(i);
                if (sig.getSignatureValue() == null || sig.getSignatureValue().getValue() == null
                                || sig.getSignatureValue().getValue().length == 0) {
                    signatures.remove(sig);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Remove invalid sig: " + sig.getId());
                    }
                    bOk = false;
                    removed++;
                }
            }
        } while (!bOk);
        return removed;
    }

    /**
     * Helper method to create the xml header
     * 
     * @return xml header
     */
    private String xmlHeader() {
        StringBuffer sb = new StringBuffer("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        if (format.equals(FORMAT_DIGIDOC_XML)) {
            sb.append("<SignedDoc format=\"");
            sb.append(format);
            sb.append("\" version=\"");
            sb.append(version);
            sb.append("\"");
            
            // namespace
            if (version.equals(VERSION_1_3)) {
                sb.append(" xmlns=\"");
                sb.append(XMLNS_DIGIDOC);
                sb.append("\"");
            }
            
            sb.append(">\n");
        }
        return sb.toString();
    }

    /**
     * Helper method to create the xml trailer
     * 
     * @return xml trailer
     */
    private String xmlTrailer() {
        if (format.equals(FORMAT_DIGIDOC_XML))
            return "\n</SignedDoc>";
        else
            return "";
    }

    /**
     * Converts the SignedDoc to XML form
     * 
     * @return XML representation of SignedDoc
     */
    public String toXML() {
        StringBuffer sb = new StringBuffer(xmlHeader());

        for (int i = 0; i < countDataFiles(); i++) {
            DataFile df = getDataFile(i);
            String str = df.toString();
            sb.append(str);
            sb.append("\n");
        }

        for (int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            String str = sig.toString();
            sb.append(str);
            sb.append("\n");
        }
        
        sb.append(xmlTrailer());

        return sb.toString();
    }

    public String toString() {
        return toXML();
    }

}
