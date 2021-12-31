const cbor = require('cbor-js');
const { webcrypto } = require('crypto');
const base32Decode = require('base32-decode');
const { getDidDoc } = require('./did.js');


/**
 * Get latest well known (did doc)
 */
const didDoc = getDidDoc();

/**
 * Offical Issuer identies
 */
const VALID_ISSUERS = ["did:web:nzcp.identity.health.nz"];

/**
 * Fail codes
 */
const VERIFY_FAILURE_REASON = {
    INVALID_QR_CODE: "INVALID_QR_CODE",
    INVALID_PASS_VERSION: "INVALID_PASS_VERSION",
    INVALID_PAYLOAD_ENCODING: "INVALID_PAYLOAD_ENCODING",
    INVALID_CBOR_STRUCTURE: "INVALID_CBOR_STRUCTURE",
    INVALID_HEADERS: "INVALID_HEADERS",
    UNSUPPORTED_ISSUER: "UNSUPPORTED_ISSUER",
    PASS_NOT_VALID_YET: "PASS_NOT_VALID_YET",
    PASS_EXPIRED: "PASS_EXPIRED",
    ISSUER_KEY_FETCH_FAILED: "ISSUER_KEY_FETCH_FAILED",
    ISSUER_KEY_MISSING: "ISSUER_KEY_MISSING",
    INVALID_SIGNATURE: "INVALID_SIGNATURE",
    INVALID_PAYLOAD: "INVALID_PAYLOAD",
};


/**
 * Verify passport
 * @param pass decoded qr result
 */
async function verifier(pass) {
    /**
     * Check if the payload received from the QR Code begins with the prefix NZCP:/, if it does not then fail.
     */
    if (!pass.startsWith("NZCP:/")) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_QR_CODE,
        };
    }

    /**
     * Parse the character(s) (representing the version-identifier) as an unsigned integer following the NZCP:/ suffix and before the next slash character (/) encountered. If this errors then fail. If the value returned is un-recognized as a major protocol version supported by the verifying software then fail. NOTE - for instance in this version of the specification this value MUST be 1.
     */
    const parts = pass.split("/");
    if (parts.length !== 3 || parts[1] !== "1") {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PASS_VERSION,
        };
    }

    /**
     * With the remainder of the payload following the / after the version-identifier, attempt to decode it using base32 as defined by [RFC4648] NOTE add back in padding if required, if an error is encountered during decoding then fail.
     */
    const VALID_B32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".split("");
    if ([...parts[2]].some((char) => !VALID_B32_CHARS.includes(char))) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD_ENCODING,
        };
    }

    let decoded = null;
    try {
        decoded = base32Decode(parts[2], 'RFC4648');
    } catch {
        // Ignore
    }
    if (!decoded) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD_ENCODING,
        };
    }

    /**
     * With the decoded payload attempt to decode it as COSE_Sign1 CBOR structure, if an error is encountered during decoding then fail.
     */
    const passStruct = cbor.decode(decoded);
    const [ headers, _, payload, signers] = passStruct;

    /**
     * Decoding the byte string present in the first element of the Decoded COSE structure, as a CBOR structure and rendering it via the expanded form yields the following. Let this result be known as the Decoded CWT protected headers.
     */
    const decodedCWTProtectedHeaders = cbor.decode(new Uint8Array(headers).buffer);

    const KID_KEY = 4;
    const ALG_KEY = 1;
    const ES256_ALG_ID = -7;

    /**
     * alg: Algorithm as per Cryptographic Digital Signature Algorithm. The claim key of 1 is used to identify this claim. It MUST be present in the protected header section of the COSE_Sign1 structure and its claim value MUST be set to the value corresponding to ES256 algorithm registration, which is the numeric value of -7 as per IANA registry.
     */
    if (decodedCWTProtectedHeaders[ALG_KEY] !== ES256_ALG_ID) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_HEADERS,
        };
    }

    /**
     * kid: This header MUST be present in the protected header section of the COSE_Sign1 structure. The claim key of 4 is used to identify this claim. Its value corresponds to a relative reference to the key used to verify the pass, which MUST be combined with the value in the iss claim in the payload in accordance with the processing rules outlined in section 6. This value MUST be encoded as a Major Type 3 string as defined by [RFC7049].
     */
    if (!decodedCWTProtectedHeaders[KID_KEY]||
        !(decodedCWTProtectedHeaders[KID_KEY] instanceof Uint8Array)) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_HEADERS,
        };
    }

    const kidDecoder = new TextDecoder();
    const kid = kidDecoder.decode(decodedCWTProtectedHeaders[KID_KEY]);

    /**
     * Decoding the byte string present in the third element of the Decoded COSE structure, as a CBOR structure and rendering it via the expanded form yields the following. Let this result be known as the Decoded CWT payload.
     */
    const decodedCWTPayload = cbor.decode(new Uint8Array(payload).buffer);

    const CTI_KEY = 7;
    const ISS_KEY = 1;
    const NBF_KEY = 5;
    const EXP_KEY = 4;
    const VC_KEY = "vc";

    /**
     * cti: CWT Token ID, this claim represents a unique identifier for the pass, it MUST be present and its decoded value MUST be a valid UUID in the form of a URI as specified by [RFC4122]. The value of this identifier MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different pass. It is RECOMMENDED that the UUID be generated in accordance with version 4 as specified by [RFC4122]. This claim is mapped to the (Credential ID) property in the W3C VC standard. The claim key for cti of 7 MUST be used.
     */
    if (!decodedCWTPayload[CTI_KEY] ||
        !(decodedCWTPayload[CTI_KEY] instanceof Uint8Array)) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    /**
     * iss: Issuer, this claim represents the party who issued the pass, it MUST be present and its decoded value MUST be a Decentralized Identifier who’s DID Method MUST correspond to web which is defined by the did:web specification. Verifying parties MUST validate this field via the verification rules outlined in section 6 This claim is mapped to the (Credential Issuer) property in the W3C VC standard. The claim key for iss of 1 MUST be used.
     */
    const iss = decodedCWTPayload[ISS_KEY];
    if (!iss || !VALID_ISSUERS.includes(iss)) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.UNSUPPORTED_ISSUER,
        };
    }

    /**
     * nbf: Not Before, this claim represents the earliest datetime at which the pass is considered valid by the party who issued it, this claim MUST be present and its value MUST be a timestamp encoded as an integer in the NumericDate format (as specified in [RFC8392] section 2). Verifying parties MUST validate that the current datetime is after or equal to the value of this claim and if not they MUST reject the pass as not being active. This claim is mapped to the Credential Issuance Date property in the W3C VC standard. NOTE - As per the standard this date can be sometime in the future, from when the pass is created. The claim key for nbf of 5 MUST be used.
     */
    const nbfSeconds = decodedCWTPayload[NBF_KEY];
    if (!nbfSeconds || typeof nbfSeconds !== "number") {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    if (nbfSeconds * 1000 > Date.now()) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.PASS_NOT_VALID_YET,
        };
    }

    /**
     * exp: Expiry, this claim represents the datetime at which the pass is considered expired by the party who issued it, this claim MUST be present and its value MUST be a timestamp encoded as an integer in the NumericDate format (as specified in [RFC8392] section 2). Verifying parties MUST validate that the current datetime is before the value of this claim and if not they MUST reject the pass as being expired. This claim is mapped to the Credential Expiration Date property in the W3C VC standard. The claim key for exp of 4 MUST be used.
     */
    const expSeconds = decodedCWTPayload[EXP_KEY];
    if (!expSeconds || typeof expSeconds !== "number") {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    if (expSeconds * 1000 < Date.now()) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.PASS_EXPIRED,
        };
    }

    /**
     * vc: Verifiable Credential CWT claim, this claim MUST be present and its value MUST follow the structure of verifiable credential claim structure. This claim is mapped to the JWT Verifiable Credential claim. The vc claim is currrently unregistered and therefore MUST be encoded as a Major Type 3 string as defined by [RFC7049].
     */
    const vc = decodedCWTPayload[VC_KEY];
    if (!vc || typeof vc !== "object") {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    const VC_FIRST_CONTEXT = "https://www.w3.org/2018/credentials/v1";

    /**
     * @context: JSON-LD Context property for conformance to the W3C VC standard. This property MUST be present and its value MUST be an array of strings where the first value MUST equal https://www.w3.org/2018/credentials/v1.
     */
    if (!vc["@context"] || !Array.isArray(vc["@context"]) ||
            vc["@context"][0] !== VC_FIRST_CONTEXT) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    /**
     * type: Type property for conformance to the W3C VC standard. This property MUST be present and its value MUST be an array of two string values, whose first element is VerifiableCredential and second element corresponds to one defined in the pass types section.
     */
    if (!vc.type || !Array.isArray(vc.type) ||
        vc.type[0] !== "VerifiableCredential" || vc.type[1] !== "PublicCovidPass") {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    /**
     * version: Version property of the New Zealand Covid Pass. This property MUST be present and its value MUST be a string who’s value corresponds to a valid version identifier as defined by semver. For the purposes of this version of the specification this value MUST be 1.0.0.
     */
    if (!vc.version || vc.version !== "1.0.0") {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    /**
     * credentialSubject: Credential Subject property MUST be present and its value MUST be a JSON object with properties determined by the declared pass type for the pass.
     */
    if (!vc.credentialSubject || typeof vc.credentialSubject !== "object") {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    const { givenName, familyName, dob } = vc.credentialSubject;
    /**
     * givenName: (REQUIRED, MAX LENGTH: 100) Given name(s) of the subject of the pass.
     */
    if (!givenName || typeof givenName !== "string" || givenName.length > 100) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    /**
     * familyName: (OPTIONAL, MAX LENGTH: 100) Family name(s) of the subject of the pass.
     */
    if (familyName && (typeof familyName !== "string" || familyName.length > 100)) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    /**
     * dob: (REQUIRED) Date of birth of the subject of the pass, in ISO 8601 date format (YYYY-MM-DD).
     */
    if (!dob || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(dob)) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.INVALID_PAYLOAD,
        };
    }

    // Validate the DID doc
    if (typeof didDoc !== "object" || didDoc.id !== iss) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.ISSUER_KEY_FETCH_FAILED,
        };
    }

    const verificationMethod = didDoc.verificationMethod.find(
        (method) => method.id === `${iss}#${kid}`
    );

    if (!verificationMethod) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.ISSUER_KEY_MISSING,
        };
    }

    const publicKeyJwk = verificationMethod.publicKeyJwk;
    if (!publicKeyJwk || typeof publicKeyJwk !== "object" ||
        !publicKeyJwk.kty || !publicKeyJwk.crv || !publicKeyJwk.x ||
        !publicKeyJwk.y) {
        return {
            verified: false,
            error: VERIFY_FAILURE_REASON.ISSUER_KEY_MISSING,
        };
    }

    const key = await webcrypto.subtle.importKey(
        "jwk",
        publicKeyJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
    );

    const externalAad = new TextEncoder().encode('');
    const signatureStruct = cbor.encode(['Signature1', headers, externalAad, payload]);

    const valid = await webcrypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        signers,
        signatureStruct
    );

    return {
        verified: valid,
        error: null,
        passport: {
            person: {
                givenName,
                familyName,
                dob,
            },
            issued: new Date(nbfSeconds * 1000),
            expires: new Date(expSeconds * 1000)
        }
    };
}


module.exports.verifier = verifier;
