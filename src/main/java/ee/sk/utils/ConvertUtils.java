/*
 * ConvertUtils.java
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

package ee.sk.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Matcher;

import org.apache.log4j.Logger;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

/**
 * Miscellaneous data conversion utility methods
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class ConvertUtils {
    
    private static final String m_dateFormat = "yyyy.MM.dd'T'HH:mm:ss'Z'";
    private static final String m_dateFormatXAdES = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static final String m_dateFormatIso8601 = "yyyy.MM.dd'T'HH:mm:ss";
    private static final String m_dateFormatSSS = "yyyy.MM.dd'T'HH:mm:ss.SSS'Z'";
    private static final String m_dateFormatXAdESSSS = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    
    private static final Logger LOG = Logger.getLogger(ConvertUtils.class);

    /**
     * Helper method to convert a Date
     * object to xsd:date format
     * 
     * @param d input data
     * @param ddoc signed doc
     * @return stringified date (xsd:date)
     * @throws DigiDocException for errors
     */
    public static String date2string(Date d, SignedDoc ddoc) {
        String str = null;
        String sF = (ddoc.getFormat().equals(SignedDoc.FORMAT_BDOC) || ddoc.getFormat().equals(SignedDoc.FORMAT_XADES)
                        || (ddoc.getVersion().equals(SignedDoc.VERSION_1_3)) ? m_dateFormatXAdES : m_dateFormat);
        SimpleDateFormat f = new SimpleDateFormat(sF);
        f.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
        str = f.format(d);
        return str;
    }
    
    public static String getTrace(Throwable ex) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        ex.printStackTrace(pw);
        return sw.toString();
    }

    /**
     * Helper method to convert a string
     * to a Date object from xsd:date format
     * 
     * @param str stringified date (xsd:date
     * @param ddoc signed doc
     * @return Date object
     * @throws DigiDocException for errors
     */
    public static Date string2date(String str, SignedDoc ddoc) throws DigiDocException {
        Date d = null;
        try {
            SimpleDateFormat f = new SimpleDateFormat((ddoc.getFormat().equals(SignedDoc.FORMAT_BDOC)
                            || ddoc.getFormat().equals(SignedDoc.FORMAT_XADES)
                            || (ddoc.getVersion().equals(SignedDoc.VERSION_1_3) || ddoc.getFormat().equals(
                                            SignedDoc.FORMAT_BDOC)) ? m_dateFormatXAdES : (ddoc.getFormat().equals(
                            SignedDoc.FORMAT_SK_XML) ? m_dateFormatIso8601 : m_dateFormat)));
            if (!ddoc.getFormat().equals(SignedDoc.FORMAT_SK_XML)) f.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
            if (str != null && str.length() > 0) {
                d = f.parse(str.trim());
            }
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_DATE_FORMAT);
        }
        return d;
    }
    
    /**
     * Helper method to convert a string
     * to a Date object from xsd:date format
     * 
     * @param str stringified date (xsd:date
     * @return Date object
     * @throws DigiDocException for errors
     */
    public static Date str2date(String str) {
        Date d = null;
        try {
            SimpleDateFormat f = new SimpleDateFormat(m_dateFormatXAdES);
            if (str != null && str.length() >= 20 && str.charAt(10) == 'T') {
                if (str.charAt(4) == '-' && str.charAt(7) == '-') {
                    if (str.length() > 20)
                        f = new SimpleDateFormat(m_dateFormatXAdESSSS);
                    else
                        f = new SimpleDateFormat(m_dateFormatXAdES);
                }
                if (str.charAt(4) == '.' && str.charAt(7) == '.') {
                    if (str.length() > 20) {
                        if (str.charAt(20) == '-')
                            f = new SimpleDateFormat(m_dateFormatIso8601);
                        else
                            f = new SimpleDateFormat(m_dateFormatSSS);
                    } else
                        f = new SimpleDateFormat(m_dateFormat);
                }
                f.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
                d = f.parse(str.trim());
            }
        } catch (Exception ex) {
            LOG.error("Error parsing date: " + str + " - " + ex);
        }
        return d;
    }

    /**
     * Helper method to convert a string
     * to a BigInteger object
     * 
     * @param str stringified date (xsd:date
     * @return BigInteger object
     * @throws DigiDocException for errors
     */
    public static BigInteger string2bigint(String str) throws DigiDocException {
        BigInteger b = null;
        try {
            if (str != null && str.length() > 0) {
                b = new BigInteger(str.trim());
            }
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NUMBER_FORMAT);
        }
        return b;
    }

    /**
     * Helper method to convert a String
     * to UTF-8
     * 
     * @param data input data
     * @param codepage codepage of input bytes
     * @return UTF-8 string
     * @throws DigiDocException for errors
     */
    public static byte[] data2utf8(byte[] data, String codepage) throws DigiDocException {
        byte[] bdata = null;
        try {
            String str = new String(data, codepage);
            bdata = str.getBytes("UTF-8");
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return bdata;
    }
    
    /**
     * Converts to UTF-8 byte array
     * 
     * @param str input data
     * @return byte array of string in desired codepage
     * @throws DigiDocException for errors
     */
    public static byte[] str2data(String str) throws DigiDocException {
        return str2data(str, "UTF-8");
    }

    /**
     * Helper method to convert a String
     * to byte array of any codepage
     * 
     * @param data input data
     * @param codepage codepage of output bytes
     * @return byte array of string in desired codepage
     * @throws DigiDocException for errors
     */
    public static byte[] str2data(String str, String codepage) throws DigiDocException {
        byte[] bdata = null;
        try {
            bdata = str.getBytes(codepage);
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return bdata;
    }
    
    /**
     * Helper method to convert a String
     * to UTF-8
     * 
     * @param data input data
     * @param codepage codepage of input bytes
     * @return UTF-8 string
     * @throws DigiDocException for errors
     */
    public static String data2str(byte[] data, String codepage) throws DigiDocException {
        String str = null;
        try {
            str = new String(data, codepage);
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return str;
    }
    
    /**
     * Converts a byte array to hex string
     * 
     * @param arr byte array input data
     * @return hex string
     */
    public static String bin2hex(byte[] arr) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < arr.length; i++) {
            String str = Integer.toHexString((int) arr[i]);
            if (str.length() == 2) sb.append(str);
            if (str.length() < 2) {
                sb.append("0");
                sb.append(str);
            }
            if (str.length() > 2) sb.append(str.substring(str.length() - 2));
        }
        return sb.toString();
    }
    
    /**
     * Helper method to convert an UTF-8
     * String to non-utf8 string
     * 
     * @param UTF-8 input data
     * @return normal string
     * @throws DigiDocException for errors
     */
    public static String utf82str(String data) throws DigiDocException {
        String str = null;
        try {
            byte[] bdata = data.getBytes();
            str = new String(bdata, "UTF-8");
        } catch (Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_UTF8_CONVERT);
        }
        return str;
    }
    
    /**
     * Checks if the certificate identified by this CN is
     * a known TSA cert
     * 
     * @param cn certificates common name
     * @return true if this is a known TSA cert
     */
    public static boolean isKnownTSACert(String cn) {
        //    	int nTsas = ConfigManager.instance().getIntProperty("DIGIDOC_TSA_COUNT", 0);
        //    	for(int i = 0; i < nTsas; i++) {
        //    		String s = ConfigManager.instance().getProperty("DIGIDOC_TSA" + (i+1) + "_CN");
        //    		if(s != null && s.equals(cn))
        //    			return true;
        //    	} // TODO: is TSA needed?
        return false;
    }
    
    public static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);

        // Get the size of the file
        long length = file.length();

        if (length > Integer.MAX_VALUE) {
            // File is too large
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int) length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }

        // Close the input stream and return bytes
        is.close();
        return bytes;
    }
    
    public static String uriDecode(String s1) {
        if (s1 == null || s1.length() == 0) return s1;
        try {
            String s = s1;
            s = replaceStr(s, '+', "%2B");
            s = URLDecoder.decode(s, "UTF-8");
            if (LOG.isDebugEnabled()) {
                LOG.debug("URI: " + s1 + " decoded: " + s);
            }
            return s;
        } catch (Exception ex) {
            LOG.error("Error decoding bytes: " + ex);
        }
        return null;
    }
    
    private static String replaceStr(String src, char c1, String rep) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; (src != null) && (i < src.length()); i++) {
            char c2 = src.charAt(i);
            if (c2 == c1) {
                sb.append(rep);
            } else {
                sb.append(c2);
            }
        }
        return sb.toString();
    }

    /*
     * Not converting:
     * (From RFC 2396 "URI Generic Syntax")
     * reserved = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | ","
     * mark = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
     */
    public static String uriEncode(String s1) {
        try {
            String s = s1;
            if (LOG.isDebugEnabled()) LOG.debug("Before uri-enc: " + s);
            s = URLEncoder.encode(s, "UTF-8");
            s = replaceStr(s, '+', "%20");
            // restore mark chars that got converted
            s = s.replaceAll("%21", "!");
            s = s.replaceAll("%40", "@");
            s = s.replaceAll("%27", "\'");
            s = s.replaceAll("%24", Matcher.quoteReplacement("$"));
            s = s.replaceAll("%7E", "~");
            s = s.replaceAll("%26", Matcher.quoteReplacement("&amp;"));
            s = s.replaceAll("%28", "(");
            s = s.replaceAll("%29", ")");
            s = s.replaceAll("%3D", "=");
            s = s.replaceAll("%2B", "+");
            s = s.replaceAll("%2C", ",");
            s = s.replaceAll("%3B", ";");
            s = s.replaceAll("%2F", "/");
            s = s.replaceAll("%3F", "?");
            s = s.replaceAll("%3A", ":");
            if (LOG.isDebugEnabled()) LOG.debug("URI: " + s1 + " encoded: " + s);
            return s;
        } catch (Exception ex) {
            LOG.error("Error encoding bytes: " + ex);
        }
        return null;
    }
    
    public static String escapeXmlSymbols(String s1) {
        if (s1 == null || s1.length() == 0) return s1;
        StringBuffer sb = new StringBuffer();
        try {
            for (int i = 0; i < s1.length(); i++) {
                char c1 = s1.charAt(i);
                if (c1 == '&') {
                    sb.append("&amp;");
                } else if (c1 == '<') {
                    sb.append("&lt;");
                } else if (c1 == '>') {
                    sb.append("&gt;");
                } else if (c1 == '\r') {
                    sb.append("&#xD;");
                } else if (c1 == '\'') {
                    sb.append("&apos;");
                } else if (c1 == '\"') {
                    sb.append("&quot;");
                } else
                    sb.append(c1);
            }
        } catch (Exception ex) {
            LOG.error("Error converting bytes: " + ex);
        }
        return sb.toString();
    }
    
    public static String escapeTextNode(String s1) {
        if (s1 == null || s1.length() == 0) return s1;
        StringBuffer sb = new StringBuffer();
        try {
            for (int i = 0; i < s1.length(); i++) {
                char c1 = s1.charAt(i);
                if (c1 == '&') {
                    sb.append("&amp;");
                } else if (c1 == '<') {
                    sb.append("&lt;");
                } else if (c1 == '>') {
                    sb.append("&gt;");
                } else if (c1 == '\r') {
                    sb.append("&#xD;");
                } else
                    sb.append(c1);
            }
        } catch (Exception ex) {
            LOG.error("Error converting bytes: " + ex);
        }
        return sb.toString();
    }
    
    public static String unescapeXmlSymbols(String s1) {
        String s2 = s1.replaceAll("&lt;", "<");
        s2 = s2.replaceAll("&gt;", ">");
        s2 = s2.replaceAll("&gt;", ">");
        s2 = s2.replaceAll("&#xD;", "\r");
        s2 = s2.replaceAll("&apos;", "'");
        s2 = s2.replaceAll("&quot;", "\"");
        s2 = s2.replaceAll("&amp;", "&");
        s2 = s2.replaceAll("&#xA;", "\n");
        return s2;
    }
}
