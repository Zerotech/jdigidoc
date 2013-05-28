package ee.sk.digidoc.tsl;

import java.util.ArrayList;
import java.util.List;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL TrustServiceStatusList type
 * 
 * @author Veiko Sinivee
 */
public class TrustServiceStatusList {
    
    /** type */
    private String type;
    
    /** TSP services */
    private List<TSPService> TSPservices;
    
    public static final String TYPE_LOCAL = "LOCAL";

    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
    
    public List<TSPService> getServices() {
        return TSPservices;
    }
    
    public TSPService getTSPService(int n) {
        if (TSPservices != null && n >= 0 && n < TSPservices.size())
            return TSPservices.get(n);
        else
            return null;
    }
    
    public void addTSPService(TSPService a) {
        if (TSPservices == null) TSPservices = new ArrayList<TSPService>();
        TSPservices.add(a);
    }
    
    public int getNumServices() {
        return ((TSPservices != null) ? TSPservices.size() : 0);
    }
    
    public boolean isLocal() {
        return type != null && type.equals(TYPE_LOCAL);
    }
    
    /**
     * Returns elements stringified form for debugging
     * 
     * @return elements stringified form
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("[TrustServiceStatusList");
        sb.append(" type=" + type + " ");
        if (TSPservices != null) {
            for (int i = 0; i < TSPservices.size(); i++)
                sb.append(TSPservices.get(i));
        }
        sb.append("]");
        return sb.toString();
    }
}
