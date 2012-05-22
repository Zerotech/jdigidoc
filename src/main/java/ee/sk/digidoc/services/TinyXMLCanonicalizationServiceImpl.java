package ee.sk.digidoc.services;

import java.io.ByteArrayOutputStream;

import ee.sk.digidoc.c14n.TinyXMLCanonicalizerHandler;
import ee.sk.digidoc.c14n.TinyXMLParser;

public class TinyXMLCanonicalizationServiceImpl implements CanonicalizationService {

    /**
     * will parse the xml document and return its canonicalized version
     */
    public byte[] canonicalize(byte[] data, String uri) {
        TinyXMLParser p;
        TinyXMLCanonicalizerHandler h;
        byte[] byteArray3;

        p = new TinyXMLParser();
        h = new TinyXMLCanonicalizerHandler();
        p.Parse(h, TinyXMLCanonicalizationServiceImpl.normalizeLineBreaks(data));
        byteArray3 = h.get_Bytes();
        return byteArray3;
    }

    public static byte[] normalizeLineBreaks(byte[] data) {
        int len;
        ByteArrayOutputStream o;
        byte[] n;
        int i;
        byte c;
        boolean skip;

        len = ((int) data.length);
        o = new ByteArrayOutputStream(len);
        n = new byte[] { 10 };

        for (i = 0; (i < len); i++) {
            c = data[i];

            if ((c == 13)) {
                skip = false;

                if (((i + 1) < len)) {
                    c = data[(i + 1)];

                    if ((c == 10)) {
                        skip = true;
                    }

                }

                if (!skip) {
                    o.write(n, (int) 0, (int) 1);
                }

            } else {
                o.write(data, i, (int) 1);
            }

        }

        return o.toByteArray();
    }

}
