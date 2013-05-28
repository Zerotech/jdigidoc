package ee.sk.digidoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import ee.sk.utils.ConvertUtils;

/**
 * Models contents of a BDOC format manifest.xml file
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class Manifest implements Serializable {

    /** manifest urn */
    private static final String MANIFEST_URN = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    public static final String MANIFEST_BDOC_MIME_1_0 = "application/vnd.bdoc-1.0";
    public static final String MANIFEST_BDOC_MIME_1_1 = "application/vnd.bdoc-1.1";
    /** file entries */
    private List<ManifestFileEntry> fileEntries;
    
    /**
     * Retrieves number of <file-entry> elements
     * 
     * @return number of <file-entry> elements
     */
    public int getNumFileEntries() {
        return ((fileEntries != null) ? fileEntries.size() : 0);
    }
    
    /**
     * Retrieves the desired <file-entry> element
     * 
     * @param nIdx index of entry
     * @return desired <file-entry> element or null if not existent
     */
    public ManifestFileEntry getFileEntry(int nIdx) {
        if (nIdx >= 0 && fileEntries != null && nIdx < fileEntries.size())
            return fileEntries.get(nIdx);
        else
            return null;
    }
    
    // mutators
    
    /**
     * Adds a new <file-entry>
     * 
     * @param fe <file-entry> element to add
     */
    public void addFileEntry(ManifestFileEntry fe) {
        if (fileEntries == null) fileEntries = new ArrayList<ManifestFileEntry>();
        fileEntries.add(fe);
    }
    
    /**
     * Removes a <file-entry>
     * 
     * @param nIdx index of entry
     */
    public void removeFileEntry(int nIdx) {
        if (nIdx >= 0 && fileEntries != null && nIdx < fileEntries.size()) fileEntries.remove(nIdx);
    }
    
    /**
     * Removes a <file-entry>
     * 
     * @param fullPath full-path of entry
     */
    public void removeFileEntryWithPath(String fullPath) {
        for (int i = 0; (fileEntries != null) && (i < fileEntries.size()); i++) {
            ManifestFileEntry fe = fileEntries.get(i);
            if (fe.getFullPath().equals(fullPath)) fileEntries.remove(i);
        }
    }
    
    /**
     * Finds a file-entry by path
     * 
     * @param fullPath full-path of entry
     * @return file-entry if found
     */
    public ManifestFileEntry findFileEntryByPath(String fullPath) {
        for (int i = 0; (fileEntries != null) && (i < fileEntries.size()); i++) {
            ManifestFileEntry fe = fileEntries.get(i);
            if (fe.getFullPath().equals(fullPath)) return fe;
        }
        return null;
    }
    
    /**
     * Converts the Manifest to XML form
     * 
     * @return XML representation of Manifest
     */
    public byte[] toXML() throws DigiDocException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(ConvertUtils.str2data("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"));
            bos.write(ConvertUtils.str2data("<manifest:manifest xmlns:manifest=\""));
            bos.write(ConvertUtils.str2data(MANIFEST_URN));
            bos.write(ConvertUtils.str2data("\">\n"));
            for (int i = 0; (fileEntries != null) && (i < fileEntries.size()); i++) {
                ManifestFileEntry fe = fileEntries.get(i);
                bos.write(fe.toXML());
            }
            bos.write(ConvertUtils.str2data("</manifest:manifest>\n"));
        } catch (IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }
    
    /**
     * return the stringified form of Manifest
     * 
     * @return Manifest string representation
     */
    public String toString() {
        String str = null;
        try {
            str = new String(toXML());
        } catch (Exception ex) {
        }
        return str;
    }
}