package ee.sk.digidoc.tsl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL TSPService type
 * 
 * @author Veiko Sinivee
 */
public class TSPService {
    
    /** service type identifier */
    private String type;
    
    /** certificates */
    private List<X509Certificate> certs;
    
    /** service access points */
    private List<String> accessPoints;
    
    // additional params
    private String CN;

    private String caCN;
    
    public static final String TSP_TYPE_CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    public static final String TSP_TYPE_OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP";
    public static final String TSP_TYPE_EXT_OCSP_QC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/OCSP-QC";

    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
    
    public List<X509Certificate> getCerts() {
        return certs;
    }
    
    public void addCertificate(X509Certificate a) {
        if (certs == null) certs = new ArrayList<X509Certificate>();
        certs.add(a);
    }
    
    public X509Certificate getCertificate(int n) {
        if (certs != null && n >= 0 && n < certs.size())
            return certs.get(n);
        else
            return null;
    }
    
    public List<String> getAccessPoints() {
        return accessPoints;
    }
    
    public void addServiceAccessPoint(String s) {
        if (accessPoints == null) accessPoints = new ArrayList<String>();
        accessPoints.add(s);
    }
    
    public String getCN() {
        return CN;
    }
    
    public void setCN(String cN) {
        CN = cN;
    }
    
    public String getCaCN() {
        return caCN;
    }
    
    public void setCaCN(String caCN) {
        this.caCN = caCN;
    }
    
    public boolean isCA() {
        return type == null || type.equals(TSP_TYPE_CA_QC);
    }
    
    public boolean isOCSP() {
        return type != null && (type.equals(TSP_TYPE_OCSP) || type.equals(TSP_TYPE_EXT_OCSP_QC));
    }
    
    /**
     * Returns elements stringified form for debugging
     * 
     * @return elements stringified form
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("[TSPService");
        sb.append(" type=" + type);
        sb.append(" cn=" + CN);
        sb.append(" ca-cn=" + caCN + " ");
        sb.append("[Certs");
        if (certs != null) {
            for (int i = 0; i < certs.size(); i++)
                sb.append(" cert=" + certs.get(i).getSubjectDN().getName());
        }
        sb.append("]");
        if (accessPoints != null && accessPoints.size() > 0) {
            sb.append("[AccessPoints");
            for (int i = 0; i < accessPoints.size(); i++)
                sb.append(" uri=" + accessPoints.get(i));
            sb.append("]");
        }
        sb.append("]");
        return sb.toString();
    }
}
