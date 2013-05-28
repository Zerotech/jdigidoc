/*
 * Notary.java
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
import java.util.Date;
import java.util.List;

/**
 * Models an OCSP confirmation of the validity of a given signature in the given
 * context.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class Notary implements Serializable {
    /** notary id (in XML) */
    private String id;
    /** OCSP response data */
    private byte[] ocspResponseData;
    /** OCSP responder id */
    private String responderId;
    /** response production timestamp */
    private Date producedAt;
    /** certificate serial number used for this notary */
    private String certNr;

    public Notary() {
    }

    /**
     * Creates new Notary and
     * 
     * @param id
     *            new Notary id
     * @param resp
     *            OCSP response data
     */
    public Notary(String id, byte[] resp, String respId, Date prodAt) {
        this.ocspResponseData = resp;
        this.id = id;
        this.responderId = respId;
        this.producedAt = prodAt;
    }

    public String getId() {
        return id;
    }

    public void setId(String str) {
        id = str;
    }

    public String getCertNr() {
        return certNr;
    }

    public void setCertNr(String nr) {
        certNr = nr;
    }

    public Date getProducedAt() {
        return producedAt;
    }

    public void setProducedAt(Date dt) {
        producedAt = dt;
    }

    public String getResponderId() {
        return responderId;
    }

    public void setResponderId(String str) {
        responderId = str;
    }

    public void setOcspResponseData(byte[] data) {
        ocspResponseData = data;
    }

    public byte[] getOcspResponseData() {
        return ocspResponseData;
    }

    /**
     * Helper method to validate the whole SignedProperties object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public List<DigiDocException> validate() {
        return new ArrayList<DigiDocException>();
    }
}
