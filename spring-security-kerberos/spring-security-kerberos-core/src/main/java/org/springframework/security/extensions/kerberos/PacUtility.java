package org.springframework.security.extensions.kerberos;

import java.io.ByteArrayOutputStream;
import java.util.StringTokenizer;

/**
 * User: Grant Cermak - grant.cermak@gmail.com
 * Date: Nov 29, 2010
 * Time: 1:37:40 PM
 */
public class PacUtility {
    // Shim function to adapt PAC string representation of byte array into other functions
    public static String binarySidToStringSid(String SID) {
        // A SID is always 28 bytes - http://msdn.microsoft.com/en-us/library/cc221018%28v=PROT.13%29.aspx
        byte[] bytes = new byte[28];
        int byteNum = 0;

        // parse unsigned SID represented as \01\05\00\00\00\00\00\05\15\00\00\00\dc\2f\15\0b\e5\76\d3\8c\be\0b\4e\be\01\02\00\00
        // into corresponding signed byte array (in Java bytes are signed so we need to do a little fancy footwork)
        for (int i = 0; i < SID.length(); i++) {
            char c = SID.charAt(i);


            if (c == '\\') {
                int highByte = Character.digit(SID.charAt(++i), 16);
                int lowByte = Character.digit(SID.charAt(++i), 16);

                int value = 16 * highByte + lowByte;

                // convert the byte to a signed value, Java requires this since byte is signed
                if (value < 128)
                    bytes[byteNum++] = (byte) value;
                else
                    bytes[byteNum++] = (byte) (value - 256);
            }
        }

        return binarySidToStringSid(bytes);
    }

    // Cribbed from http://www.jroller.com/eyallupu/entry/java_jndi_how_to_convert
    public static String binarySidToStringSid(byte[] SID) {
        StringBuilder strSID = new StringBuilder("S-");

        // bytes[0] : in the array is the version (must be 1 but might
        // change in the future)
        strSID.append(SID[0]).append('-');

        // bytes[2..7] : the Authority
        StringBuilder tmpBuff = new StringBuilder();
        for (int t = 2; t <= 7; t++) {
            String hexString = Integer.toHexString(SID[t] & 0xFF);
            tmpBuff.append(hexString);
        }
        strSID.append(Long.parseLong(tmpBuff.toString(), 16));

        // bytes[1] : the sub authorities count
        int count = SID[1];

        // bytes[8..end] : the sub authorities (these are Integers - notice
        // the endian)
        for (int i = 0; i < count; i++) {
            int currSubAuthOffset = i * 4;
            tmpBuff.setLength(0);
            tmpBuff.append(String.format("%02X%02X%02X%02X",
                    (SID[11 + currSubAuthOffset] & 0xFF),
                    (SID[10 + currSubAuthOffset] & 0xFF),
                    (SID[9 + currSubAuthOffset] & 0xFF),
                    (SID[8 + currSubAuthOffset] & 0xFF)));

            strSID.append('-').append(Long.parseLong(tmpBuff.toString(), 16));
        }

        return strSID.toString();
    }

    // Cribbed from http://forums.sun.com/thread.jspa?threadID=5155925
    public static byte[] stringSidToByteArraySid(String SID) {
        ByteArrayOutputStream obyte = new ByteArrayOutputStream();
        StringTokenizer tokens = new StringTokenizer(SID, "-");

        int idx = 0, sub_authorities_sz = 0;
        long[] sub_authorities_buff = new long[8];
        while (tokens.hasMoreElements()) {
            String sval = (String) tokens.nextElement();
            long val = 0;
            try {
                val = Long.parseLong(sval);
            } catch (NumberFormatException e) {
                idx++;
                continue; // skip S.
            }

            // SID revision
            if (idx == 1)
                obyte.write((byte) (val & 0xFF));
                // 48-bit SID authority
            else if (idx == 2) {
                byte[] bval = longToByteArray(val);
                obyte.write(bval[0]);
                obyte.write(bval[1]);
                obyte.write(bval[2]);
                obyte.write(bval[3]);
                obyte.write(bval[4]);
                obyte.write(bval[5]);
                // N number of 32-bit SID sub-authorities.
            } else {
                sub_authorities_buff[idx - 3] = val;
                sub_authorities_sz++;
            }

            idx++;
        }

        // Write the number of SID sub-authorities.
        obyte.write((byte) sub_authorities_sz);

        // Write each SID sub-authority.
        for (int i = 0; i < sub_authorities_sz; i++) {
            byte[] bval = longToByteArray(sub_authorities_buff[i]);
            obyte.write(bval[0]);
            obyte.write(bval[1]);
            obyte.write(bval[2]);
            obyte.write(bval[3]);
        }

        return obyte.toByteArray();
    }

    // Cribbed from http://forums.sun.com/thread.jspa?threadID=5155925
    private static byte[] longToByteArray(long value) {
        byte[] result = new byte[8];

        // FYI - The effect of this operation is to break
        // down the long into an array of eight bytes.
        //
        // What's going on: The FF selects selects the byte
        // of interest within value. The the >> shifts the
        // target bits to the right the desired result. The
        // shift ensures the result will fit into a single
        // 8-bit byte. Depending upon the byte of interest
        // it must be shifted appropriately so it's always
        // in the lower-order 8-bits.

        result[0] = (byte) (value & 0x00000000000000FFL);
        result[1] = (byte) ((value & 0x000000000000FF00L) >> 8);
        result[2] = (byte) ((value & 0x0000000000FF0000L) >> 16);
        result[3] = (byte) ((value & 0x00000000FF000000L) >> 24);
        result[4] = (byte) ((value & 0x000000FF00000000L) >> 32);
        result[5] = (byte) ((value & 0x0000FF0000000000L) >> 40);
        result[6] = (byte) ((value & 0x00FF000000000000L) >> 48);
        result[7] = (byte) ((value & 0xFF00000000000000L) >> 56);

        return result;
    }
}
