package com.varwof.aic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The AIC X.509v3 extension value (draft §5.1 / Go {@code types.AIC}).
 *
 * <p>DER:
 * <pre>
 * SEQUENCE {
 *   INTEGER version                     (DEFAULT 1)
 *   UTF8String agentId
 *   PrincipalUid principalUid
 *   SEQUENCE OF Capability capabilities
 *   INTEGER delegationMode              (DEFAULT 0)
 *   [0] EXPLICIT SEQUENCE OF Capability authorizationConstraints OPTIONAL
 *   DelegationAuthorization delegationAuthorization OPTIONAL   (required by spec)
 *   [1] EXPLICIT SEQUENCE OF ExtField extensions OPTIONAL
 * }
 * </pre>
 */
public record Aic(
        int version,
        String agentId,
        PrincipalUid principalUid,
        List<Capability> capabilities,
        DelegationMode delegationMode,
        List<Capability> authorizationConstraints,
        DelegationAuthorization delegationAuthorization,
        List<ExtField> extensions) {

    public Aic {
        agentId = Objects.requireNonNull(agentId, "agentId");
        principalUid = Objects.requireNonNull(principalUid, "principalUid");
        capabilities = capabilities == null ? List.of() : List.copyOf(capabilities);
        delegationMode = Objects.requireNonNull(delegationMode, "delegationMode");
        authorizationConstraints = authorizationConstraints == null ? List.of() : List.copyOf(authorizationConstraints);
        extensions = extensions == null ? List.of() : List.copyOf(extensions);
    }

    public static AicBuilder builder() {
        return new AicBuilder();
    }

    /** Copy with a (new) DelegationAuthorization attached. */
    public Aic withDelegationAuthorization(DelegationAuthorization da) {
        return new Aic(version, agentId, principalUid, capabilities, delegationMode,
                authorizationConstraints, da, extensions);
    }

    /** Communication-form principal string {@code {realm}:{identifier}:{fp}}. */
    public String principal() {
        return principalUid.displayString();
    }

    /** True when the agent carries at least one capability with the given scheme. */
    public boolean hasProtocol(String schemeId) {
        for (Capability c : capabilities) {
            if (c.schemeId().equals(schemeId)) {
                return true;
            }
        }
        return false;
    }

    /** True when any capability full ID matches {@code required} (glob). */
    public boolean checkPermission(String required) {
        for (Capability c : capabilities) {
            if (CapabilityMatcher.matchCapability(c.fullId(), required)) {
                return true;
            }
        }
        return false;
    }

    /** Full IDs of capabilities that match any granted pattern. */
    public List<String> intersectPermissions(PrincipalAuthorization pa) {
        if (pa == null) {
            return List.of();
        }
        return intersectPermissions(pa.grantIds());
    }

    public List<String> intersectPermissions(List<String> grantPatterns) {
        if (capabilities.isEmpty() || grantPatterns.isEmpty()) {
            return List.of();
        }
        Map<String, String> seen = new LinkedHashMap<>();
        List<String> result = new ArrayList<>();
        for (Capability c : capabilities) {
            String full = c.fullId();
            if (seen.containsKey(full)) {
                continue;
            }
            for (String p : grantPatterns) {
                if (CapabilityMatcher.matchCapability(full, p)) {
                    seen.put(full, full);
                    result.add(full);
                    break;
                }
            }
        }
        return result;
    }

    public List<String> intersectPermissionsStrAny(String commaOrSpaceDelimited) {
        if (commaOrSpaceDelimited == null || commaOrSpaceDelimited.isEmpty()) {
            return List.of();
        }
        List<String> perms = new ArrayList<>();
        for (String tok : commaOrSpaceDelimited.split("[, ]")) {
            if (!tok.isEmpty()) {
                perms.add(tok);
            }
        }
        return perms.isEmpty() ? List.of() : intersectPermissions(perms);
    }

    public byte[] encode() {
        List<ASN1Encodable> elems = new ArrayList<>();
        elems.add(Der.integer(version));
        elems.add(Der.utf8(agentId));
        elems.add(asn1Of(principalUid.encode()));
        elems.add(encodeCapabilities(capabilities));
        elems.add(Der.integer(delegationMode.value));
        if (!authorizationConstraints.isEmpty()) {
            elems.add(Der.explicit(0, encodeCapabilities(authorizationConstraints)));
        }
        if (delegationAuthorization != null && delegationAuthorization.isPresent()) {
            elems.add(asn1Of(delegationAuthorization.encode()));
        }
        if (!extensions.isEmpty()) {
            elems.add(Der.explicit(1, encodeExtensions(extensions)));
        }
        return Der.der(Der.derSequence(elems.toArray(new ASN1Encodable[0])));
    }

    private static ASN1Primitive asn1Of(byte[] der) {
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (java.io.IOException ex) {
            throw new AicException("Aic: bad nested DER", ex);
        }
    }

    private static ASN1Primitive encodeCapabilities(List<Capability> caps) {
        ASN1Encodable[] arr = caps.stream().map(c -> asn1Of(c.encode())).toArray(ASN1Encodable[]::new);
        return Der.derSequence(arr).toASN1Primitive();
    }

    private static ASN1Primitive encodeExtensions(List<ExtField> exts) {
        ASN1Encodable[] arr = exts.stream().map(e -> asn1Of(e.encode())).toArray(ASN1Encodable[]::new);
        return Der.derSequence(arr).toASN1Primitive();
    }

    public static Aic decode(ASN1Encodable e) {
        ASN1Sequence seq = Der.seq(e);
        if (seq.size() < 5) {
            throw new AicException("Aic: expected at least 5 elements, got " + seq.size());
        }
        int version = Der.intValue(seq.getObjectAt(0));
        String agentId = Der.stringValue(seq.getObjectAt(1));
        PrincipalUid uid = PrincipalUid.decode(seq.getObjectAt(2));
        List<Capability> caps = decodeCapabilities(seq.getObjectAt(3));
        List<Capability> constraints = List.of();
        DelegationAuthorization da = null;
        List<ExtField> exts = List.of();
        DelegationMode mode = null;
        for (int ix = 4; ix < seq.size(); ix++) {
            ASN1Encodable elem = seq.getObjectAt(ix);
            ASN1Primitive inner = Der.optionalTagContent(elem, 0);
            if (inner != null) {
                constraints = decodeCapabilities(inner);
                continue;
            }
            inner = Der.optionalTagContent(elem, 1);
            if (inner != null) {
                exts = decodeExtensions(inner);
                continue;
            }
            if (elem.toASN1Primitive() instanceof ASN1Integer) {
                mode = DelegationMode.fromValue(Der.intValue(elem));
                continue;
            }
            if (elem.toASN1Primitive() instanceof ASN1Sequence) {
                da = DelegationAuthorization.decode(elem);
                continue;
            }
            throw new AicException("Aic: unexpected element at index " + ix);
        }
        if (mode == null) {
            mode = DelegationMode.AUTHORIZED;
        }
        return new Aic(version, agentId, uid, caps, mode, constraints, da, exts);
    }

    public static Aic parse(byte[] derBytes) {
        try {
            return decode(ASN1Primitive.fromByteArray(derBytes));
        } catch (java.io.IOException ex) {
            throw new AicException("Aic: bad DER", ex);
        }
    }

    static List<Capability> decodeCapabilities(ASN1Encodable e) {
        ASN1Sequence seq = Der.seq(e);
        List<Capability> out = new ArrayList<>(seq.size());
        for (int i = 0; i < seq.size(); i++) {
            out.add(Capability.decode(seq.getObjectAt(i)));
        }
        return out;
    }

    private static List<ExtField> decodeExtensions(ASN1Encodable e) {
        ASN1Sequence seq = Der.seq(e);
        List<ExtField> out = new ArrayList<>(seq.size());
        for (int i = 0; i < seq.size(); i++) {
            out.add(ExtField.decode(seq.getObjectAt(i)));
        }
        return out;
    }

    /** Fluent builder; {@code da} and constraints/actions can be added after construction. */
    public static class AicBuilder {
        private int version = 1;
        private String agentId = "";
        private PrincipalUid principalUid;
        private final List<Capability> capabilities = new ArrayList<>();
        private DelegationMode delegationMode = DelegationMode.AUTHORIZED;
        private final List<Capability> authorizationConstraints = new ArrayList<>();
        private DelegationAuthorization delegationAuthorization;
        private final List<ExtField> extensions = new ArrayList<>();

        public AicBuilder version(int v) {
            this.version = v;
            return this;
        }

        public AicBuilder agentId(String id) {
            this.agentId = id;
            return this;
        }

        public AicBuilder principalUid(PrincipalUid uid) {
            this.principalUid = uid;
            return this;
        }

        public AicBuilder capability(Capability c) {
            this.capabilities.add(c);
            return this;
        }

        public AicBuilder capabilities(List<Capability> caps) {
            this.capabilities.addAll(caps);
            return this;
        }

        public AicBuilder delegationMode(DelegationMode mode) {
            this.delegationMode = mode;
            return this;
        }

        public AicBuilder constraint(Capability c) {
            this.authorizationConstraints.add(c);
            return this;
        }

        public AicBuilder delegationAuthorization(DelegationAuthorization da) {
            this.delegationAuthorization = da;
            return this;
        }

        public List<Capability> capabilitiesView() {
            return capabilities;
        }

        public List<Capability> constraintsView() {
            return authorizationConstraints;
        }

        public List<ExtField> extensionsView() {
            return extensions;
        }

        public Aic build() {
            if (principalUid == null) {
                throw new AicException("Aic: principalUid is required");
            }
            return new Aic(version, agentId, principalUid, capabilities, delegationMode,
                    authorizationConstraints, delegationAuthorization, extensions);
        }
    }
}