package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;

import java.util.ArrayList;
import java.util.List;

/**
 * PrincipalAuthorization principal grants (Go {@code types.PrincipalAuthorization}).
 *
 * <pre>
 * SEQUENCE {
 *   INTEGER version (DEFAULT 1),
 *   SEQUENCE OF Capability grants OPTIONAL,
 *   [0] EXPLICIT SEQUENCE OF Capability authorizationConstraints OPTIONAL,
 *   [1] EXPLICIT DelegationPolicy delegationPolicy OPTIONAL,
 *   [2] EXPLICIT SEQUENCE OF ExtField extensions OPTIONAL
 * }
 * </pre>
 *
 * <p>Go's {@code delegationPolicy asn1:"optional,explicit,tag:1"} has no
 * {@code omitempty}, so a zero-valued policy is still emitted when the field
 * precedes extensions; {@code null} here means the optional field is omitted.
 */
public record PrincipalAuthorization(
        int version,
        List<Capability> grants,
        List<Capability> authorizationConstraints,
        DelegationPolicy delegationPolicy,
        List<ExtField> extensions) {

    public PrincipalAuthorization {
        grants = grants == null ? List.of() : List.copyOf(grants);
        authorizationConstraints = authorizationConstraints == null ? List.of() : List.copyOf(authorizationConstraints);
        extensions = extensions == null ? List.of() : List.copyOf(extensions);
    }

    public static PrincipalAuthorizationBuilder builder() {
        return new PrincipalAuthorizationBuilder();
    }

    public List<String> grantIds() {
        List<String> ids = new ArrayList<>(grants.size());
        for (Capability g : grants) {
            ids.add(g.fullId());
        }
        return ids;
    }

    public boolean allowsRepresentative() {
        return delegationPolicy != null && delegationPolicy.allowsRepresentative();
    }

    public byte[] encode() {
        List<ASN1Encodable> elems = new ArrayList<>();
        elems.add(Der.integer(version));
        if (!grants.isEmpty()) {
            elems.add(encodeCapabilities(grants));
        }
        if (!authorizationConstraints.isEmpty()) {
            elems.add(Der.explicit(0, encodeCapabilities(authorizationConstraints)));
        }
        if (delegationPolicy != null) {
            elems.add(Der.explicit(1, asn1Of(delegationPolicy.encode())));
        }
        if (!extensions.isEmpty()) {
            elems.add(Der.explicit(2, encodeExtensions(extensions)));
        }
        return Der.der(Der.derSequence(elems.toArray(new ASN1Encodable[0])));
    }

    public static PrincipalAuthorization decode(ASN1Encodable e) {
        org.bouncycastle.asn1.ASN1Sequence seq = Der.seq(e);
        if (seq.size() < 1) {
            throw new AicException("PrincipalAuthorization: empty SEQUENCE");
        }
        int version = Der.intValue(seq.getObjectAt(0));
        List<Capability> grants = List.of();
        List<Capability> constraints = List.of();
        DelegationPolicy policy = null;
        List<ExtField> exts = List.of();
        for (int ix = 1; ix < seq.size(); ix++) {
            ASN1Encodable elem = seq.getObjectAt(ix);
            ASN1Primitive inner;
            if ((inner = Der.optionalTagContent(elem, 0)) != null) {
                constraints = Aic.decodeCapabilities(inner);
            } else if ((inner = Der.optionalTagContent(elem, 1)) != null) {
                policy = DelegationPolicy.decode(inner);
            } else if ((inner = Der.optionalTagContent(elem, 2)) != null) {
                exts = decodeExtensions(inner);
            } else {
                grants = Aic.decodeCapabilities(elem);
            }
        }
        return new PrincipalAuthorization(version, grants, constraints, policy, exts);
    }

    public static PrincipalAuthorization parse(byte[] derBytes) {
        try {
            return decode(ASN1Primitive.fromByteArray(derBytes));
        } catch (java.io.IOException ex) {
            throw new AicException("PrincipalAuthorization: bad DER", ex);
        }
    }

    private static ASN1Primitive asn1Of(byte[] der) {
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (java.io.IOException ex) {
            throw new AicException("PrincipalAuthorization: bad nested DER", ex);
        }
    }

    private static ASN1Primitive encodeCapabilities(List<Capability> caps) {
        return Der.derSequence(caps.stream().map(c -> asn1Of(c.encode())).toArray(ASN1Encodable[]::new)).toASN1Primitive();
    }

    private static List<ExtField> decodeExtensions(ASN1Encodable inner) {
        org.bouncycastle.asn1.ASN1Sequence s = Der.seq(inner);
        List<ExtField> out = new ArrayList<>(s.size());
        for (int i = 0; i < s.size(); i++) {
            out.add(ExtField.decode(s.getObjectAt(i)));
        }
        return out;
    }

    private static ASN1Primitive encodeExtensions(List<ExtField> exts) {
        return Der.derSequence(exts.stream().map(e -> asn1Of(e.encode())).toArray(ASN1Encodable[]::new)).toASN1Primitive();
    }

    /** Fluent builder. */
    public static class PrincipalAuthorizationBuilder {
        private int version = 1;
        private final List<Capability> grants = new ArrayList<>();
        private final List<Capability> constraints = new ArrayList<>();
        private DelegationPolicy policy;
        private final List<ExtField> extensions = new ArrayList<>();

        public PrincipalAuthorizationBuilder version(int v) {
            this.version = v;
            return this;
        }

        public PrincipalAuthorizationBuilder grant(Capability c) {
            this.grants.add(c);
            return this;
        }

        public PrincipalAuthorizationBuilder grants(List<Capability> caps) {
            this.grants.addAll(caps);
            return this;
        }

        public PrincipalAuthorizationBuilder constraint(Capability c) {
            this.constraints.add(c);
            return this;
        }

        public PrincipalAuthorizationBuilder policy(DelegationPolicy p) {
            this.policy = p;
            return this;
        }

        public List<Capability> grantsView() {
            return grants;
        }

        public PrincipalAuthorization build() {
            return new PrincipalAuthorization(version, grants, constraints, policy, extensions);
        }
    }
}