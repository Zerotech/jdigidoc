package ee.sk.digidoc;

import java.io.Serializable;

/**
 * Models the QualifyingProperties element of an BDOC.
 * 
 * @author Kalev Suik
 * @version 1.0
 */

public class QualifyingProperties implements Serializable {
    private String target;

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

}
