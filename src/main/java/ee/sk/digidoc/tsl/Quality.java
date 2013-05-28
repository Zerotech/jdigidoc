package ee.sk.digidoc.tsl;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL QualityElement
 * 
 * @author Veiko Sinivee
 */
public class Quality {
    
    /** quality name or URI */
    private String name;
    /** quality value */
    private int value = 0;
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public int getValue() {
        return value;
    }
    
    public void setValue(int value) {
        this.value = value;
    }
    
    /**
     * Returns elements stringified form for debugging
     * 
     * @return elements stringified form
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("[Quality");
        sb.append(" name=" + name);
        sb.append(" value=" + value);
        sb.append("]");
        return sb.toString();
    }
}
