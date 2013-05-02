package ee.sk.digidoc.tsl;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL MultiLangString type
 * 
 * @author Veiko Sinivee
 */
public class MultiLangString {
    
    /** lang attribute */
    private String lang;
    /** value of string */
    private String value;
    
    /**
     * Default constructor for MultiLangString
     */
    public MultiLangString() {}
    
    /**
     * Paramterized constrctor for MultiLangString
     * 
     * @param lang lang attribute
     * @param value value of string
     */
    public MultiLangString(String lang, String value) {
        this.lang = lang;
        this.value = value;
    }
    
    public String getLang() {
        return lang;
    }
    
    public void setLang(String lang) {
        this.lang = lang;
    }
    
    public String getValue() {
        return value;
    }
    
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Returns elements stringified form for debugging
     * 
     * @return elements stringified form
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("[MultiLangString");
        sb.append(" lang=" + lang);
        sb.append(" value=" + value);
        sb.append("]");
        return sb.toString();
    }
}
