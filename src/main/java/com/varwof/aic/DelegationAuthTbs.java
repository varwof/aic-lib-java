package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * To-be-signed data for the DelegationAuthorization signature (Go
 * {@code types.DelegationAuthTBS}).
 *
 * <p>Field order: version, agentId, principalUid, reason, capabilities,
 * delegationMode, authorizationConstraints, requestedLifetime, timestamp,
 * nonce.
 */
public final class DelegationAuthTbs {
    public final int version;
    public final String agentId;
    public final PrincipalUid principalUid;
    public final Reason reason;
    public final List<Capability> capabilities;
    public final DelegationMode delegationMode;
    public final List<Capability> authorizationConstraints;
    public final int requestedLifetime;
    public final Instant timestamp;
    public final byte[] nonce;

    public DelegationAuthTbs(int version, String agentId, PrincipalUid principalUid, Reason reason,
                             List<Capability> capabilities, DelegationMode delegationMode,
                             List<Capability> authorizationConstraints, int requestedLifetime,
                             Instant timestamp, byte[] nonce) {
        this.version = version;
        this.agentId = Objects.requireNonNull(agentId, "agentId");
        this.principalUid = Objects.requireNonNull(principalUid, "principalUid");
        this.reason = Objects.requireNonNull(reason, "reason");
        this.capabilities = List.copyOf(capabilities == null ? List.of() : capabilities);
        this.delegationMode = Objects.requireNonNull(delegationMode, "delegationMode");
        this.authorizationConstraints = List.copyOf(authorizationConstraints == null ? List.of() : authorizationConstraints);
        this.requestedLifetime = requestedLifetime;
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
        this.nonce = nonce == null ? null : nonce.clone();
    }

    /** Build the TBS from the corresponding (unsigned) {@link Aic}. */
    public static DelegationAuthTbs fromAic(Aic aic) {
        return new DelegationAuthTbs(
                aic.version(),
                aic.agentId(),
                aic.principalUid(),
                aic.delegationAuthorization() == null ? Reason.EMPTY : aic.delegationAuthorization().reason(),
                aic.capabilities(),
                aic.delegationMode(),
                aic.authorizationConstraints(),
                aic.delegationAuthorization() == null ? 0 : aic.delegationAuthorization().requestedLifetime(),
                aic.delegationAuthorization() == null ? Instant.EPOCH : aic.delegationAuthorization().timestamp(),
                aic.delegationAuthorization() == null ? null : aic.delegationAuthorization().nonce());
    }

    public byte[] encode() {
        List<ASN1Encodable> elems = new ArrayList<>();
        elems.add(Der.integer(version));
        elems.add(Der.utf8(agentId));
        elems.add(asn1Of(principalUid.encode()));
        elems.add(asn1Of(reason.encode()));
        elems.add(encodeCapabilities(capabilities));
        elems.add(Der.integer(delegationMode.value));
        if (authorizationConstraints != null && !authorizationConstraints.isEmpty()) {
            elems.add(Der.explicit(0, encodeCapabilities(authorizationConstraints)));
        }
        elems.add(Der.integer(requestedLifetime));
        elems.add(Der.generalized(timestamp));
        elems.add(new DEROctetString(nonce == null ? new byte[0] : nonce));
        return Der.der(Der.derSequence(elems.toArray(new ASN1Encodable[0])));
    }

    private static ASN1Primitive asn1Of(byte[] der) {
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (java.io.IOException ex) {
            throw new AicException("DelegationAuthTbs: bad nested DER", ex);
        }
    }

    private static ASN1Primitive encodeCapabilities(List<Capability> caps) {
        ASN1Encodable[] arr = caps.isEmpty()
                ? new ASN1Encodable[0]
                : caps.stream().map(c -> asn1Of(c.encode())).toArray(ASN1Encodable[]::new);
        return Der.derSequence(arr).toASN1Primitive();
    }

    public static DelegationAuthTbs decode(ASN1Encodable e) {
        ASN1Sequence seq = Der.seq(e);
        int ix = 0;
        int version = Der.intValue(seq.getObjectAt(ix++));
        String agentId = Der.stringValue(seq.getObjectAt(ix++));
        PrincipalUid uid = PrincipalUid.decode(seq.getObjectAt(ix++));
        Reason reason = Reason.decode(seq.getObjectAt(ix++));
        List<Capability> caps = decodeCapabilities(seq.getObjectAt(ix++));
        // Remaining elements are strictly ordered per encode()/Go: delegationMode,
        // optional [0] constraints, requestedLifetime, timestamp, nonce.
        if (ix >= seq.size() || !(seq.getObjectAt(ix).toASN1Primitive() instanceof org.bouncycastle.asn1.ASN1Integer modeInt)) {
            throw new AicException("DelegationAuthTbs: delegationMode missing");
        }
        DelegationMode mode = DelegationMode.fromValue((int) modeInt.getValue().longValue());
        ix++;
        List<Capability> constraints = List.of();
        if (ix < seq.size()) {
            ASN1Primitive tagInner = Der.optionalTagContent(seq.getObjectAt(ix), 0);
            if (tagInner != null) {
                constraints = decodeCapabilities(tagInner);
                ix++;
            }
        }
        if (ix >= seq.size() || !(seq.getObjectAt(ix).toASN1Primitive() instanceof org.bouncycastle.asn1.ASN1Integer life)) {
            throw new AicException("DelegationAuthTbs: requestedLifetime missing");
        }
        int lifetime = (int) life.getValue().longValue();
        ix++;
        if (ix >= seq.size() || !(seq.getObjectAt(ix).toASN1Primitive() instanceof org.bouncycastle.asn1.ASN1GeneralizedTime gt)) {
            throw new AicException("DelegationAuthTbs: timestamp missing");
        }
        Instant ts = Der.toInstant(gt);
        ix++;
        if (ix >= seq.size() || !(seq.getObjectAt(ix).toASN1Primitive() instanceof org.bouncycastle.asn1.ASN1OctetString oct)) {
            throw new AicException("DelegationAuthTbs: nonce missing");
        }
        byte[] nonce = oct.getOctets();
        ix++;
        if (ix != seq.size()) {
            throw new AicException("DelegationAuthTbs: unexpected trailing elements");
        }
        return new DelegationAuthTbs(version, agentId, uid, reason, caps, mode, constraints, lifetime, ts, nonce);
    }

    public static DelegationAuthTbs parse(byte[] derBytes) {
        try {
            return decode(ASN1Primitive.fromByteArray(derBytes));
        } catch (java.io.IOException ex) {
            throw new AicException("DelegationAuthTbs: bad DER", ex);
        }
    }

    private static List<Capability> decodeCapabilities(ASN1Encodable e) {
        ASN1Sequence seq = Der.seq(e);
        List<Capability> out = new ArrayList<>(seq.size());
        for (int i = 0; i < seq.size(); i++) {
            out.add(Capability.decode(seq.getObjectAt(i)));
        }
        return out;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DelegationAuthTbs that)) {
            return false;
        }
        return version == that.version
                && requestedLifetime == that.requestedLifetime
                && agentId.equals(that.agentId)
                && principalUid.equals(that.principalUid)
                && reason.equals(that.reason)
                && capabilities.equals(that.capabilities)
                && delegationMode == that.delegationMode
                && authorizationConstraints.equals(that.authorizationConstraints)
                && timestamp.equals(that.timestamp)
                && Arrays.equals(nonce, that.nonce);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, agentId, principalUid, reason, capabilities,
                delegationMode, authorizationConstraints, requestedLifetime, timestamp, Arrays.hashCode(nonce));
    }
}