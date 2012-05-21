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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import ee.sk.digidoc.services.CanonicalizationService;
import ee.sk.utils.ConvertUtils;

/**
 * Represents an instance of signed doc in DIGIDOC format. Contains one or more
 * DataFile -s and zero or more Signature -s.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class SignedDoc implements Serializable {

    private String format;

    private String version;

    private List<DataFile> dataFiles;

    private List<Signature> signatures;

    public static final String FORMAT_SK_XML = "SK-XML";
    public static final String FORMAT_DIGIDOC_XML = "DIGIDOC-XML";
    public static final String FORMAT_BDOC = "BDOC";

    public static final String VERSION_1_0 = "1.0";
    public static final String VERSION_1_1 = "1.1";
    public static final String VERSION_1_2 = "1.2";
    public static final String VERSION_1_3 = "1.3";
    public static final String VERSION_1_4 = "1.4";

    public static final String BDOC_VERSION_1_0 = "1.0";

    /** the only supported algorithm is SHA1 */
    public static final String SHA1_DIGEST_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#sha1";
    /** SHA1 digest data is always 20 bytes */
    public static final int SHA1_DIGEST_LENGTH = 20;
    /** the only supported canonicalization method is 20010315 */
    public static final String CANONICALIZATION_METHOD_20010315 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /** the only supported signature method is RSA-SHA1 */
    public static final String RSA_SHA1_SIGNATURE_METHOD = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    /** the only supported transform is digidoc detatched transform */
    public static final String DIGIDOC_DETATCHED_TRANSFORM = "http://www.sk.ee/2002/10/digidoc#detatched-document-signature";

    public static final String SIGNEDPROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

    public static final String XMLNS_XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

    public static final String XMLNS_ETSI = "http://uri.etsi.org/01903/v1.1.1#";

    public static final String XMLNS_DIGIDOC = "http://www.sk.ee/DigiDoc/v1.3.0#";

    public static final String XMLNS_XADES_123 = "http://uri.etsi.org/01903/v1.3.2#";

    public static final String SIG_FILE_NAME = "META-INF/signature";
    public static final String MIMET_FILE_NAME = "mimetype";
    public static final String MIMET_FILE_CONTENT = "application/vnd.bdoc";
    public static final String MANIF_FILE_NAME = "META-INF/manifest.xml";

    
    public SignedDoc() {
    }

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
        setFormat(format);
        setVersion(version);
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

        if (str == null 
                || (!str.equals(FORMAT_BDOC) && !str.equals(FORMAT_SK_XML) && !str.equals(FORMAT_DIGIDOC_XML))
                || (str.equals(FORMAT_SK_XML) && version != null && !version.equals(VERSION_1_0))
                || (str.equals(FORMAT_BDOC) && version != null && !version.equals(BDOC_VERSION_1_0))
                || (str.equals(FORMAT_DIGIDOC_XML) && version != null && !version.equals(VERSION_1_1)
                        && !version.equals(VERSION_1_2) && !version.equals(VERSION_1_3))) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "Currently supports only SK-XML, DIGIDOC-XML and BDOC formats", null);
        }
            
        return ex;
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

        if (str == null || (!str.equals(VERSION_1_0) && !str.equals(VERSION_1_1) && !str.equals(VERSION_1_2) && !str.equals(VERSION_1_3) && !str.equals(VERSION_1_4) && !str.equals(BDOC_VERSION_1_0))) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION, "Currently supports only versions 1.0, 1.1, 1.2, 1.3 and 1.4 but not " + str, null);
        } else if (str.equals(VERSION_1_0) && format != null && !format.equals(FORMAT_SK_XML) && !FORMAT_BDOC.equalsIgnoreCase(format)) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION, "Version is 1.0 but does not support" + format, null);
        } else if ((str.equals(VERSION_1_1) || str.equals(VERSION_1_2) || str.equals(VERSION_1_3) || str.equals(VERSION_1_4)) && format != null && !format.equals(FORMAT_DIGIDOC_XML)) {
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION, "Currently supports versions 1.0, 1.1, 1.2, 1.3 and 1.4 but not " + format, null);
        }

        return ex;
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
        DataFile df = new DataFile(getNewDataFileId(), contentType, inputFile.getAbsolutePath(), mime, this);
        addDataFile(df);
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
        if (FORMAT_BDOC.equals(format)) {
            try {
                ZipOutputStream zos = new ZipOutputStream(os);
                writeMimetypeFile(zos);
                writeToZipStream(zos);
                zos.close();
                return;
            } catch (DigiDocException ex) {
                throw ex; // allready handled
            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
            }
        }

        // TODO read DataFile elements from old file
        try {
            os.write(xmlHeader().getBytes());
            
            for (int i = 0; i < countDataFiles(); i++) {
                DataFile df = getDataFile(i);
                df.writeToFile(os);
                os.write("\n".getBytes());
            }
            
            for (int i = 0; i < countSignatures(); i++) {
                Signature sig = getSignature(i);
                os.write(sig.toXML());
                os.write("\n".getBytes());
            }
            
            os.write(xmlTrailer().getBytes());
        } catch (DigiDocException ex) {
            throw ex; // already handled
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    // A Inga <2008 aprill> BDOCiga seotud muudatused xml-is 1
    /**
     * Writes the mimetype file to a zip stream
     * 
     * @param os
     *            ZipOutputStream
     * @throws DigiDocException
     *             for all errors
     */
    private void writeMimetypeFile(ZipOutputStream zos) throws DigiDocException {
        try {
            ByteArrayOutputStream mimeBos = new ByteArrayOutputStream();
            // write mimetype file
            mimeBos.write(ConvertUtils.str2data(MIMET_FILE_CONTENT));
            mimeBos.write(ConvertUtils.str2data("-"));
            mimeBos.write(ConvertUtils.str2data(getVersion()));
            zos.putNextEntry(new ZipEntry(MIMET_FILE_NAME));
            zos.write(mimeBos.toByteArray());
            // Complete the entry
            zos.closeEntry();

        } catch (DigiDocException ex) {
            throw ex; // allready handled
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    /**
     * Writes the SignedDoc to a zip stream
     * 
     * @param os
     *            ZipOutputStream
     * @throws DigiDocException
     *             for all errors
     */
    private void writeToZipStream(ZipOutputStream zos) throws DigiDocException {
        try {
            ByteArrayOutputStream manifestBos = new ByteArrayOutputStream();

            // write manifest file
            manifestBos.write(ConvertUtils.str2data("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"));
            manifestBos
                    .write(ConvertUtils
                            .str2data("<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">\n"));
            manifestBos
                    .write(ConvertUtils.str2data("<manifest:file-entry manifest:media-type=\"application/vnd.bdoc-"));
            manifestBos.write(ConvertUtils.str2data(this.getVersion()));
            manifestBos.write(ConvertUtils.str2data("\" manifest:full-path=\"/\" />\n"));

            for (int i = 0; i < countDataFiles(); i++) {
                DataFile df = getDataFile(i);
                // A Inga <2008 aprill> BDOCiga seotud muudatused xml-is 1.2
                File file = new File(df.getFullName());
                // L Inga <2008 aprill> BDOCiga seotud muudatused xml-is 1.2

                // Add add file to output stream.
                zos.putNextEntry(new ZipEntry(file.getName()));
                zos.write(df.getBytesFromFile());

                // Complete the entry
                zos.closeEntry();

                // create manifest
                manifestBos.write(ConvertUtils.str2data("<manifest:file-entry manifest:media-type=\""));
                manifestBos.write(ConvertUtils.str2data(df.getMimeType()));
                manifestBos.write(ConvertUtils.str2data("\" manifest:full-path=\""));
                manifestBos.write(ConvertUtils.str2data((file.getName())));
                manifestBos.write(ConvertUtils.str2data("\" />\n"));
            }
            for (int i = 0; i < countSignatures(); i++) {
                Signature sig = getSignature(i);
                // Add add sig to output stream.
                int iSigNr = i + 1;
                zos.putNextEntry(new ZipEntry(SIG_FILE_NAME + iSigNr + ".xml"));
                String xmlHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
                zos.write(xmlHeader.getBytes());
                zos.write(sig.toXML());
                zos.write("\n".getBytes());
                // Complete the entry
                zos.closeEntry();

                manifestBos.write(ConvertUtils.str2data("<manifest:file-entry manifest:media-type=\""));
                manifestBos.write(ConvertUtils.str2data("signature/bdoc"));
                // BDOC is always in lower case, no matter what
                // manifestBos.write(ConvertUtils.str2data(getFormat()));
                manifestBos.write(ConvertUtils.str2data("-"));
                manifestBos.write(ConvertUtils.str2data(getVersion()));
                // TODO DIGIDOC_WITH_TS /TS or /TM
                manifestBos.write(ConvertUtils.str2data("/TM"));

                manifestBos.write(ConvertUtils.str2data("\" manifest:full-path=\""));
                // FIXME kas pole nii, et siganture failid kirjutavad üksteist
                // üle?
                manifestBos.write(ConvertUtils.str2data(SIG_FILE_NAME + iSigNr + ".xml"));
                manifestBos.write(ConvertUtils.str2data("\" />\n"));
            }
            manifestBos.write(ConvertUtils.str2data("</manifest:manifest>"));
            zos.putNextEntry(new ZipEntry(MANIF_FILE_NAME));
            zos.write(manifestBos.toByteArray());
            // Complete the entry
            zos.closeEntry();
        } catch (DigiDocException ex) {
            throw ex; // allready handled
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }

    // L Inga <2008 aprill> BDOCiga seotud muudatused xml-is 1

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
        if (countSignatures() > 0)
            throw new DigiDocException(DigiDocException.ERR_SIGATURES_EXIST,
                    "Cannot remove DataFiles when signatures exist!", null);
        dataFiles.remove(idx);
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
            if (sig.getId().equals(sigId))
                return sig;
        }
        return null;
    }

    /**
     * Adds a new uncomplete signature to signed doc
     * 
     * @param cert
     *            signers certificate
     * @param claimedRoles
     *            signers claimed roles
     * @param adr
     *            signers address
     * @return new Signature object
     */
    public Signature prepareSignature(X509Certificate cert, String[] claimedRoles, SignatureProductionPlace adr, CanonicalizationService canonicalizationService)
            throws DigiDocException {
        Signature sig = new Signature(this);
        sig.setId(getNewSignatureId());
        // create SignedInfo block
        SignedInfo si = new SignedInfo(sig, RSA_SHA1_SIGNATURE_METHOD, CANONICALIZATION_METHOD_20010315);
        // add DataFile references
        for (int i = 0; i < countDataFiles(); i++) {
            DataFile df = getDataFile(i);
            Reference ref = new Reference(si, df);
            si.addReference(ref);
        }
        // create key info
        KeyInfo ki = new KeyInfo(cert);
        sig.setKeyInfo(ki);
        ki.setSignature(sig);
        CertValue cval = new CertValue();
        cval.setType(CertValue.CERTVAL_TYPE_SIGNER);
        cval.setCert(cert);
        sig.addCertValue(cval);
        CertID cid = new CertID(sig, cert, CertID.CERTID_TYPE_SIGNER);
        sig.addCertID(cid);
        // create signed properties
        SignedProperties sp = new SignedProperties(sig, cert, claimedRoles, adr);
        Reference ref = new Reference(si, sp, canonicalizationService);
        // A Kalev <2008 aprill> BDOCiga seotud muudatused xml-is 1
        ref.setType(SignedDoc.SIGNEDPROPERTIES_TYPE);
        // A Kalev <2008 aprill> BDOCiga seotud muudatused xml-is 1
        si.addReference(ref);
        sig.setSignedInfo(si);
        sig.setSignedProperties(sp);
        addSignature(sig);
        return sig;
    }

    /**
     * Adds a new Signature object
     * 
     * @param attr
     *            Signature object to add
     */
    public void addSignature(Signature sig) {
        if (signatures == null)
            signatures = new ArrayList<Signature>();
        signatures.add(sig);
    }

    /**
     * return the desired Signature object
     * 
     * @param idx
     *            index of the Signature object
     * @return desired Signature object
     */
    public Signature getSignature(int idx) {
        return (Signature) signatures.get(idx);
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
        if (signatures != null && signatures.size() > 0)
            return (Signature) signatures.get(signatures.size() - 1);
        else
            return null;
    }

    /**
     * Deletes last signature
     */
    public void removeLastSiganture() {
        if (signatures.size() > 0)
            signatures.remove(signatures.size() - 1);
    }


    /**
     * Helper method to create the xml header
     * 
     * @return xml header
     */
    private String xmlHeader() {
        StringBuffer sb = new StringBuffer("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
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
        return sb.toString();
    }

    /**
     * Helper method to create the xml trailer
     * 
     * @return xml trailer
     */
    private String xmlTrailer() {
        return "\n</SignedDoc>";
    }

    /**
     * Converts the SignedDoc to XML form
     * 
     * @return XML representation of SignedDoc
     */
    public String toXML() throws DigiDocException {
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

    @Override
    public String toString() {
        try {
            return toXML();
        } catch (DigiDocException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Computes an SHA1 digest
     * 
     * @param data
     *            input data
     * @return SHA1 digest
     */
    public static byte[] digest(byte[] data) throws DigiDocException {
        byte[] dig = null;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(data);
            dig = sha.digest();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        return dig;
    }

    /**
     * return certificate owners first name
     * 
     * @return certificate owners first name or null
     */
    public static String getSubjectFirstName(X509Certificate cert) {
        String name = null;
        String dn = cert.getSubjectDN().getName();
        int idx1 = dn.indexOf("CN=");
        if (idx1 != -1) {
            while (idx1 < dn.length() - 1 && dn.charAt(idx1) != ',')
                idx1++;
            if (idx1 < dn.length() - 1)
                idx1++;
            int idx2 = idx1;
            while (idx2 < dn.length() - 1 && dn.charAt(idx2) != ',' && dn.charAt(idx2) != '/')
                idx2++;
            name = dn.substring(idx1, idx2);
        }
        return name;
    }

    /**
     * return certificate owners last name
     * 
     * @return certificate owners last name or null
     */
    public static String getSubjectLastName(X509Certificate cert) {
        String name = null;
        String dn = cert.getSubjectDN().getName();
        int idx1 = dn.indexOf("CN=");
        if (idx1 != -1) {
            idx1 += 2;
            while (idx1 < dn.length() - 1 && !Character.isLetter(dn.charAt(idx1)))
                idx1++;
            int idx2 = idx1;
            while (idx2 < dn.length() - 1 && dn.charAt(idx2) != ',' && dn.charAt(idx2) != '/')
                idx2++;
            name = dn.substring(idx1, idx2);
        }
        return name;
    }

    /**
     * return certificate owners personal code
     * 
     * @return certificate owners personal code or null
     */
    public static String getSubjectPersonalCode(X509Certificate cert) {
        String code = null;
        String dn = cert.getSubjectDN().getName();
        int idx1 = dn.indexOf("CN=");
        // System.out.println("DN: " + dn);
        if (idx1 != -1) {
            while (idx1 < dn.length() - 1 && !Character.isDigit(dn.charAt(idx1)))
                idx1++;
            int idx2 = idx1;
            while (idx2 < dn.length() - 1 && Character.isDigit(dn.charAt(idx2)))
                idx2++;
            code = dn.substring(idx1, idx2);
        }
        // System.out.println("Code: " + code);
        return code;
    }

    // VS: 02.01.2009 - fix finding ocsp responders cert
    /**
     * return certificate's fingerprint
     * 
     * @param cert
     *            X509Certificate object
     * @return certificate's fingerprint or null
     */
    public static byte[] getCertFingerprint(X509Certificate cert) {
        byte[] bdat = cert.getExtensionValue("2.5.29.14");
        if (bdat != null) {
            if (bdat.length > 20) {
                byte[] bdat2 = new byte[20];
                System.arraycopy(bdat, bdat.length - 20, bdat2, 0, 20);
                return bdat2;
            } else
                return bdat;
        }

        return null;
    }

    // VS: 02.01.2009 - fix finding ocsp responders cert

    /**
     * return CN part of DN
     * 
     * @return CN part of DN or null
     */
    public static String getCommonName(String dn) {
        String name = null;
        if (dn != null) {
            int idx1 = dn.indexOf("CN=");
            if (idx1 != -1) {
                idx1 += 2;
                while (idx1 < dn.length() && !Character.isLetter(dn.charAt(idx1)))
                    idx1++;
                int idx2 = idx1;
                while (idx2 < dn.length() && dn.charAt(idx2) != ',' && dn.charAt(idx2) != '/')
                    idx2++;
                name = dn.substring(idx1, idx2);
            }
        }
        return name;
    }

    /**
     * Reads X509 certificate from a data stream
     * 
     * @param data
     *            input data in Base64 form
     * @return X509Certificate object
     * @throws EFormException
     *             for all errors
     */
    public static X509Certificate readCertificate(byte[] data) throws DigiDocException {
        X509Certificate cert = null;
        try {
            // ByteArrayInputStream certStream = new
            // ByteArrayInputStream(Base64Util.decode(data));
            ByteArrayInputStream certStream = new ByteArrayInputStream(data);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(certStream);
            certStream.close();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_CERT);
        }
        return cert;
    }

    /**
     * Reads the cert from a file, URL or from another location somewhere in the
     * CLASSPATH such as in the librarys jar file.
     * 
     * @param certLocation
     *            certificates file name, or URL. You can use url in form
     *            jar://<location> to read a certificate from the car file or
     *            some other location in the CLASSPATH
     * @return certificate object
     */
    public static X509Certificate readCertificate(String certLocation) throws DigiDocException {
        X509Certificate cert = null;
        try {
            InputStream isCert = null;
            URL url = null;
            if (certLocation.startsWith("http")) {
                url = new URL(certLocation);
                isCert = url.openStream();
            } else if (certLocation.startsWith("jar://")) {
                isCert = SignedDoc.class.getResourceAsStream(certLocation.substring(6));
            } else {
                isCert = new FileInputStream(certLocation);
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certificateFactory.generateCertificate(isCert);
            isCert.close();
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        return cert;
    }

    /**
     * Helper method for comparing digest values
     * 
     * @param dig1
     *            first digest value
     * @param dig2
     *            second digest value
     * @return true if they are equal
     */
    public static boolean compareDigests(byte[] dig1, byte[] dig2) {
        boolean ok = (dig1 != null) && (dig2 != null) && (dig1.length == dig2.length);
        
        for (int i = 0; ok && (i < dig1.length); i++) {
            if (dig1[i] != dig2[i]) {
                ok = false;
            }
        }
        
        return ok;
    }

}
