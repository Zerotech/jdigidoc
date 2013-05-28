package ee.sk.digidoc;

import java.io.Serializable;

/**
 * Holds data of one relative distinguished name (RDN) from a DN
 * normalized according to RFC4514
 * 
 * @author Veiko Sinivee
 */
public class Rdn implements Serializable {
    /** field id or short name */
    private String id;
    /** field name or description */
    private String name;
    /** field value */
    private String value;
    
    /**
     * String X.500 AttributeType
     * ------ --------------------------------------------
     * CN commonName (2.5.4.3)
     * L localityName (2.5.4.7)
     * ST stateOrProvinceName (2.5.4.8)
     * O organizationName (2.5.4.10)
     * OU organizationalUnitName (2.5.4.11)
     * C countryName (2.5.4.6)
     * STREET streetAddress (2.5.4.9)
     * DC domainComponent (0.9.2342.19200300.100.1.25)
     * UID userId (0.9.2342.19200300.100.1.1)
     */
    
    /**
     * Default constructor for Rdn
     */
    public Rdn() {}
    
    /**
     * Parametrized constructor for Rdn
     */
    public Rdn(String id, String name, String value) {
        this.id = id;
        this.name = name;
        this.value = value;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getValue() {
        return value;
    }
    
    public void setValue(String value) {
        this.value = value;
    }
}
