package com.varwof.aic;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;

/**
 * Minimal CIDR prefix matcher (IPv4/IPv6) used by the allowed-cidr
 * constraint. Mirrors Go {@code net/netip.Prefix.Contains}.
 */
public final class Cidr {
    private final byte[] network;
    private final int prefixBits;
    private final int addrBytes;

    private Cidr(byte[] network, int prefixBits, int addrBytes) {
        this.network = network;
        this.prefixBits = prefixBits;
        this.addrBytes = addrBytes;
    }

    public static Cidr parse(String cidr) {
        try {
            int slash = cidr.lastIndexOf('/');
            if (slash < 0) {
                throw new IllegalArgumentException("missing prefix length");
            }
            String addr = cidr.substring(0, slash);
            int bits = Integer.parseInt(cidr.substring(slash + 1));
            if (!isIpLiteral(addr)) {
                throw new IllegalArgumentException("not an IP literal (\"" + addr + "\")");
            }
            InetAddress ip = InetAddress.getByName(addr);
            byte[] raw = ip.getAddress();
            int maxBits;
            if (ip instanceof Inet4Address) {
                maxBits = 32;
            } else if (ip instanceof Inet6Address) {
                maxBits = 128;
            } else {
                throw new IllegalArgumentException("unsupported address family");
            }
            if (bits < 0 || bits > maxBits) {
                throw new IllegalArgumentException("prefix length out of range");
            }
            byte[] network = Arrays.copyOf(raw, raw.length);
            int fullBytes = bits / 8;
            int rem = bits % 8;
            if (fullBytes < network.length) {
                for (int i = fullBytes + 1; i < network.length; i++) {
                    network[i] = 0;
                }
                if (rem > 0) {
                    network[fullBytes] &= (byte) (0xff << (8 - rem));
                } else {
                    network[fullBytes] = 0;
                }
            }
            return new Cidr(network, bits, raw.length);
        } catch (Exception ex) {
            throw new AicException("invalid CIDR \"" + cidr + "\": " + ex.getMessage());
        }
    }

    public boolean contains(InetAddress ip) {
        byte[] raw = ip.getAddress();
        if (raw.length != addrBytes) {
            return false;
        }
        int fullBytes = prefixBits / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (raw[i] != network[i]) {
                return false;
            }
        }
        int rem = prefixBits % 8;
        if (rem > 0) {
            int mask = 0xff << (8 - rem);
            if ((raw[fullBytes] & mask) != (network[fullBytes] & mask)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        try {
            return InetAddress.getByAddress(network).getHostAddress() + "/" + prefixBits;
        } catch (Exception ex) {
            return "<cidr>";
        }
    }

    /** Rejects hostnames and non-literal addresses (Go's netip only accepts IP literals). */
    private static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        if (s.indexOf(':') >= 0) {
            // IPv6: only hex digits, ':' and '.' allowed; no zone index '%'.
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!(hex || c == ':' || c == '.')) {
                    return false;
                }
            }
            return true;
        }
        // IPv4: exactly 4 decimal octets in 0..255.
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty()) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!(p.charAt(i) >= '0' && p.charAt(i) <= '9')) {
                    return false;
                }
            }
            if (Integer.parseInt(p) > 255) {
                return false;
            }
        }
        return true;
    }
}