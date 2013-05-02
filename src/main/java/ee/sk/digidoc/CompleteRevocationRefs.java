/*
 * CompleteRevocationRefs.java
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

package ee.sk.digidoc;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Models the ETSI CompleteRevocationRefs element This contains some data from
 * the OCSP response and it's digest
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class CompleteRevocationRefs implements Serializable {
    
    private List<OcspRef> ocspRefs;

    /** parent object - UnsignedProperties ref */
    private UnsignedProperties unsignedProps;
    
    public UnsignedProperties getUnsignedProperties() {
        return unsignedProps;
    }

    public void setUnsignedProperties(UnsignedProperties uprops) {
        unsignedProps = uprops;
    }
    
    public OcspRef getOcspRefById(int nIdx) {
        if (ocspRefs != null && nIdx < ocspRefs.size())
            return ocspRefs.get(nIdx);
        else
            return null;
    }
    
    public OcspRef getOcspRefByUri(String uri) {
        if (ocspRefs != null) {
            for (OcspRef orf : ocspRefs) {
                if (orf.getUri().equals(uri)) return orf;
            }
        }
        return null;
    }
    
    public OcspRef getLastOcspRef() {
        if (ocspRefs != null && ocspRefs.size() > 0)
            return ocspRefs.get(ocspRefs.size() - 1);
        else
            return null;
    }
    
    public void addOcspRef(OcspRef orf) {
        if (ocspRefs == null) ocspRefs = new ArrayList<OcspRef>();
        ocspRefs.add(orf);
    }
    
    public int countOcspRefs() {
        return (ocspRefs != null) ? ocspRefs.size() : 0;
    }
    
    public List<DigiDocException> validate() {
        List<DigiDocException> errs = new ArrayList<DigiDocException>();
        if (ocspRefs != null) {
            for (OcspRef orf : ocspRefs) {
                List<DigiDocException> errs2 = orf.validate();
                if (errs2 != null && errs2.size() > 0) errs.addAll(errs2);
            }
        }
        return errs;
    }
}