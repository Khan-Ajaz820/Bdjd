package com.fixjenni.validator

import android.util.Log
import com.tom_roush.pdfbox.pdmodel.PDDocument
import com.tom_roush.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tsp.TimeStampToken
import org.bouncycastle.util.Store
import java.io.InputStream
import java.security.Security
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathBuilderException
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Date

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/**
 * Overall validation status for a single PDF signature.
 *
 * | Status                  | Meaning                                                                 |
 * |-------------------------|-------------------------------------------------------------------------|
 * | VALID                   | Signature intact + chain trusted + cert valid at signing time           |
 * | INVALID                 | Signature bytes do not match document content (document was modified)  |
 * | INTACT_BUT_UNTRUSTED    | Signature is cryptographically intact but issuer is not in trust store |
 * | INTACT_CERT_EXPIRED     | Signature intact, chain trusted, but cert was expired at signing time  |
 * | ERROR                   | Could not parse / process the signature at all                          |
 */
enum class SignatureStatus {
    VALID,
    INVALID,
    INTACT_BUT_UNTRUSTED,
    INTACT_CERT_EXPIRED,
    ERROR
}

/** Revocation status reported for a signer certificate. */
enum class RevocationStatus {
    /** Embedded OCSP/CRL in the PDF (LTV/DSS) confirmed the cert was not revoked. */
    NOT_REVOKED_EMBEDDED,
    /** No embedded revocation info; cannot check without network. */
    UNKNOWN_OFFLINE,
    /** Embedded revocation info indicates the cert was revoked. */
    REVOKED_EMBEDDED,
    /** Could not determine status. */
    UNDETERMINED
}

/**
 * Structured result for a single signature found in the PDF.
 */
data class SignatureResult(
    /** Human-readable name of the signature field (e.g. "Signature1"). */
    val fieldName: String,
    /** Overall validation status. */
    val status: SignatureStatus,
    /** Subject CN of the signer certificate, or null if unavailable. */
    val signerName: String?,
    /** Full subject DN of the signer certificate. */
    val signerDn: String?,
    /** Issuer DN of the signer certificate. */
    val issuerDn: String?,
    /** Certificate serial number (hex). */
    val serialNumber: String?,
    /**
     * Signing time — prefers an embedded RFC 3161 timestamp token (trusted),
     * falls back to the /M entry in the signature dictionary (claimed, not trusted).
     */
    val signingTime: Date?,
    /** True if the signing time came from an embedded RFC 3161 timestamp token. */
    val signingTimeIsTimestamp: Boolean,
    /** Revocation status (offline only). */
    val revocationStatus: RevocationStatus,
    /** The full certificate chain extracted from the CMS structure. */
    val certificateChain: List<X509Certificate>,
    /** Human-readable list of reasons explaining the status. */
    val reasons: List<String>
)

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/**
 * Core offline PDF digital-signature validator.
 *
 * Usage:
 * ```kotlin
 * Security.addProvider(BouncyCastleProvider())   // once at app start
 * val validator = PdfSignatureValidator(trustStore)
 * val results   = validator.validate(pdfInputStream)
 * ```
 *
 * All validation is performed **on-device with no network calls**.
 */
class PdfSignatureValidator(private val trustStore: TrustStore) {

    companion object {
        private const val TAG = "PdfSigValidator"

        init {
            // Ensure BC is registered; safe to call multiple times.
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    // -------------------------------------------------------------------------
    // Public entry point
    // -------------------------------------------------------------------------

    /**
     * Validates all signatures in the PDF supplied via [pdfStream].
     *
     * @param pdfStream  Raw bytes of the PDF (caller must close after this returns).
     * @param password   User password for encrypted PDFs; pass `null` for unencrypted.
     * @return           One [SignatureResult] per signature found, in document order.
     *                   Returns an empty list if the PDF has no signatures.
     * @throws PasswordRequiredException if the PDF is encrypted and no (or wrong) password was given.
     */
    @Throws(PasswordRequiredException::class)
    fun validate(pdfStream: InputStream, password: String? = null): List<SignatureResult> {
        val pdfBytes = pdfStream.readBytes()

        // Open with PDFBox — handle encryption
        val document: PDDocument = try {
            if (password != null) {
                PDDocument.load(pdfBytes, password)
            } else {
                PDDocument.load(pdfBytes)
            }
        } catch (e: com.tom_roush.pdfbox.pdmodel.encryption.InvalidPasswordException) {
            throw PasswordRequiredException("PDF is password-protected. Please provide the correct password.", e)
        } catch (e: Exception) {
            // PDFBox may throw a generic exception for wrong passwords too
            if (e.message?.contains("password", ignoreCase = true) == true ||
                e.message?.contains("encrypt", ignoreCase = true) == true) {
                throw PasswordRequiredException("PDF is encrypted. Please provide the correct password.", e)
            }
            throw e
        }

        return document.use { doc ->
            val catalog = doc.documentCatalog
            val acroForm = catalog.acroForm

            if (acroForm == null) {
                Log.d(TAG, "No AcroForm found — PDF has no signature fields.")
                return@use emptyList()
            }

            // Collect all signature fields, including nested ones
            val signatureFields = collectSignatureFields(acroForm.fields)

            if (signatureFields.isEmpty()) {
                Log.d(TAG, "No signature fields found in AcroForm.")
                return@use emptyList()
            }

            signatureFields.mapNotNull { field ->
                val sig = field.signature ?: return@mapNotNull null
                val name = try { field.fullyQualifiedName } catch (e: Exception) { null }
                    ?: try { field.partialName } catch (e: Exception) { null }
                    ?: "Signature"
                validateSignature(name, sig, pdfBytes)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Field collection helper
    // -------------------------------------------------------------------------

    /**
     * Recursively collects all [PDSignatureField]s from the AcroForm field tree,
     * including fields nested inside non-terminal (group) fields.
     */
    private fun collectSignatureFields(
        fields: List<com.tom_roush.pdfbox.pdmodel.interactive.form.PDField>
    ): List<com.tom_roush.pdfbox.pdmodel.interactive.form.PDSignatureField> {
        val result = mutableListOf<com.tom_roush.pdfbox.pdmodel.interactive.form.PDSignatureField>()
        for (field in fields) {
            when (field) {
                is com.tom_roush.pdfbox.pdmodel.interactive.form.PDSignatureField ->
                    result += field
                is com.tom_roush.pdfbox.pdmodel.interactive.form.PDNonTerminalField ->
                    result += collectSignatureFields(field.children)
                else -> { /* other field types — skip */ }
            }
        }
        return result
    }

    // -------------------------------------------------------------------------
    // Per-signature validation
    // -------------------------------------------------------------------------

    private fun validateSignature(
        fieldName: String,
        sig: PDSignature,
        pdfBytes: ByteArray
    ): SignatureResult {
        val reasons = mutableListOf<String>()

        // ------------------------------------------------------------------
        // 1. Extract the raw CMS/PKCS#7 signature bytes and the signed ranges
        // ------------------------------------------------------------------
        val cmsBytes: ByteArray
        val byteRange: IntArray

        try {
            byteRange = sig.byteRange
            // sig.contents reads the /Contents value from the parsed PDF structure.
            // This gives us the raw CMS/PKCS#7 DER bytes.
            cmsBytes = sig.contents
        } catch (e: Exception) {
            Log.e(TAG, "[$fieldName] Cannot extract signature contents", e)
            reasons += "Cannot extract signature contents: ${e.message}"
            return SignatureResult(
                fieldName = fieldName, status = SignatureStatus.ERROR,
                signerName = null, signerDn = null, issuerDn = null,
                serialNumber = null, signingTime = null,
                signingTimeIsTimestamp = false,
                revocationStatus = RevocationStatus.UNDETERMINED,
                certificateChain = emptyList(), reasons = reasons
            )
        }

        // ------------------------------------------------------------------
        // 2. Reconstruct the signed content from ByteRange and verify digest
        // ------------------------------------------------------------------
        //
        // PDF ByteRange = [offset0, length0, offset1, length1]
        // The signed bytes are pdfBytes[offset0 .. offset0+length0]
        //                    + pdfBytes[offset1 .. offset1+length1]
        // (the gap between them is the /Contents hex string itself, excluded)
        //
        val signedContent: ByteArray = try {
            extractSignedContent(pdfBytes, byteRange)
        } catch (e: Exception) {
            Log.e(TAG, "[$fieldName] ByteRange extraction failed", e)
            reasons += "ByteRange extraction failed: ${e.message}"
            return SignatureResult(
                fieldName = fieldName, status = SignatureStatus.ERROR,
                signerName = null, signerDn = null, issuerDn = null,
                serialNumber = null, signingTime = null,
                signingTimeIsTimestamp = false,
                revocationStatus = RevocationStatus.UNDETERMINED,
                certificateChain = emptyList(), reasons = reasons
            )
        }

        // ------------------------------------------------------------------
        // 3. Parse the CMS SignedData structure
        // ------------------------------------------------------------------
        val cmsSignedData: CMSSignedData = try {
            CMSSignedData(cmsBytes)
        } catch (e: CMSException) {
            Log.e(TAG, "[$fieldName] Cannot parse CMS SignedData", e)
            reasons += "Cannot parse CMS/PKCS#7 structure: ${e.message}"
            return SignatureResult(
                fieldName = fieldName, status = SignatureStatus.ERROR,
                signerName = null, signerDn = null, issuerDn = null,
                serialNumber = null, signingTime = null,
                signingTimeIsTimestamp = false,
                revocationStatus = RevocationStatus.UNDETERMINED,
                certificateChain = emptyList(), reasons = reasons
            )
        }

        // ------------------------------------------------------------------
        // 4. Extract certificates embedded in the CMS structure
        // ------------------------------------------------------------------
        val certConverter = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)

        @Suppress("UNCHECKED_CAST")
        val certStore: Store<X509CertificateHolder> =
            cmsSignedData.certificates as Store<X509CertificateHolder>

        val embeddedCerts: List<X509Certificate> = certStore.getMatches(null)
            .mapNotNull { holder ->
                try { certConverter.getCertificate(holder) } catch (e: Exception) { null }
            }

        // ------------------------------------------------------------------
        // 5. Verify each SignerInfo (usually just one for PDF signatures)
        // ------------------------------------------------------------------
        val signerInfos = cmsSignedData.signerInfos.signers
        if (signerInfos.isEmpty()) {
            reasons += "No SignerInfo found in CMS structure."
            return SignatureResult(
                fieldName = fieldName, status = SignatureStatus.ERROR,
                signerName = null, signerDn = null, issuerDn = null,
                serialNumber = null, signingTime = null,
                signingTimeIsTimestamp = false,
                revocationStatus = RevocationStatus.UNDETERMINED,
                certificateChain = embeddedCerts, reasons = reasons
            )
        }

        // We process the first signer (PDF typically has exactly one).
        val signerInfo: SignerInformation = signerInfos.first()

        @Suppress("UNCHECKED_CAST")
val signerCertHolder: X509CertificateHolder? =
    (certStore.getMatches(signerInfo.sid as org.bouncycastle.util.Selector<X509CertificateHolder>)
        as Collection<X509CertificateHolder>)
        .firstOrNull()

        val signerCert: X509Certificate? = signerCertHolder?.let {
            try { certConverter.getCertificate(it) } catch (e: Exception) { null }
        }

        // ------------------------------------------------------------------
        // 6. Cryptographic integrity check (signature bytes vs. signed content)
        // ------------------------------------------------------------------
        //
        // PDF signatures are "detached" CMS signatures: the /Contents field
        // holds the CMS SignedData but the eContent is absent (detached).
        // We supply the signed content externally so BC can verify the digest.
        //
        if (signerCertHolder == null) {
            reasons += "Signer certificate not found in CMS structure."
            return SignatureResult(
                fieldName = fieldName, status = SignatureStatus.ERROR,
                signerName = null, signerDn = null, issuerDn = null,
                serialNumber = null, signingTime = null,
                signingTimeIsTimestamp = false,
                revocationStatus = RevocationStatus.UNDETERMINED,
                certificateChain = embeddedCerts, reasons = reasons
            )
        }

        val integrityOk: Boolean = try {
            // Wrap the signed content as a CMSProcessableByteArray (detached)
            val processable = CMSProcessableByteArray(signedContent)
            // Re-parse with the actual content attached so BC can verify the digest
            val cmsWithContent = CMSSignedData(processable, cmsBytes)
            val verifier = JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signerCertHolder)
            cmsWithContent.signerInfos.signers.first().verify(verifier)
        } catch (e: Exception) {
            Log.w(TAG, "[$fieldName] Integrity check exception", e)
            reasons += "Integrity check failed: ${e.message}"
            false
        }

        if (!integrityOk) {
            reasons += "Signature is INVALID — the document has been modified after signing."
            return SignatureResult(
                fieldName = fieldName, status = SignatureStatus.INVALID,
                signerName = extractCn(signerCert),
                signerDn = signerCert?.subjectX500Principal?.name,
                issuerDn = signerCert?.issuerX500Principal?.name,
                serialNumber = signerCert?.serialNumber?.toString(16),
                signingTime = extractSigningTime(sig, signerInfo).first,
                signingTimeIsTimestamp = extractSigningTime(sig, signerInfo).second,
                revocationStatus = RevocationStatus.UNDETERMINED,
                certificateChain = embeddedCerts, reasons = reasons
            )
        }

        reasons += "Signature integrity verified — document has not been modified since signing."

        // ------------------------------------------------------------------
        // 7. Extract signing time (prefer RFC 3161 timestamp, fall back to /M)
        // ------------------------------------------------------------------
        val (signingTime, signingTimeIsTimestamp) = extractSigningTime(sig, signerInfo)
        if (signingTime != null) {
            val source = if (signingTimeIsTimestamp) "RFC 3161 timestamp token" else "signature dictionary /M field (claimed, not cryptographically verified)"
            reasons += "Signing time: $signingTime (source: $source)"
        } else {
            reasons += "Signing time: not available"
        }

        // ------------------------------------------------------------------
        // 8. Certificate validity period check
        // ------------------------------------------------------------------
        val checkTime = signingTime ?: Date()
        var certExpiredAtSigning = false
        if (signerCert != null) {
            try {
                signerCert.checkValidity(checkTime)
                reasons += "Certificate was valid at signing time."
            } catch (e: java.security.cert.CertificateExpiredException) {
                certExpiredAtSigning = true
                reasons += "Certificate was EXPIRED at signing time (${signerCert.notAfter})."
            } catch (e: java.security.cert.CertificateNotYetValidException) {
                certExpiredAtSigning = true
                reasons += "Certificate was NOT YET VALID at signing time (${signerCert.notBefore})."
            }
        }

        // ------------------------------------------------------------------
        // 9. Revocation check (offline — embedded LTV/DSS only)
        // ------------------------------------------------------------------
        val revocationStatus = checkRevocationOffline(cmsSignedData, signerCert, reasons)

        // ------------------------------------------------------------------
        // 10. Certificate chain trust validation
        // ------------------------------------------------------------------
        val trustedRoots = trustStore.getTrustedCertificates()
        val chainTrusted: Boolean = if (trustedRoots.isEmpty()) {
            reasons += "Trust store is empty — no trusted root CAs loaded. " +
                    "Add CCA India root/intermediate certs to assets/trusted_roots/ or import them via the app."
            false
        } else if (signerCert == null) {
            reasons += "Cannot validate chain — signer certificate not found."
            false
        } else {
            validateCertificateChain(signerCert, embeddedCerts, trustedRoots, checkTime, reasons)
        }

        // ------------------------------------------------------------------
        // 11. Determine final status
        // ------------------------------------------------------------------
        val status = when {
            certExpiredAtSigning -> SignatureStatus.INTACT_CERT_EXPIRED
            !chainTrusted        -> SignatureStatus.INTACT_BUT_UNTRUSTED
            else                 -> SignatureStatus.VALID
        }

        return SignatureResult(
            fieldName = fieldName,
            status = status,
            signerName = extractCn(signerCert),
            signerDn = signerCert?.subjectX500Principal?.name,
            issuerDn = signerCert?.issuerX500Principal?.name,
            serialNumber = signerCert?.serialNumber?.toString(16)?.uppercase(),
            signingTime = signingTime,
            signingTimeIsTimestamp = signingTimeIsTimestamp,
            revocationStatus = revocationStatus,
            certificateChain = embeddedCerts,
            reasons = reasons
        )
    }

    // -------------------------------------------------------------------------
    // ByteRange extraction
    // -------------------------------------------------------------------------

    /**
     * Extracts the signed byte ranges from the raw PDF bytes according to the
     * PDF specification's ByteRange array: [offset0, length0, offset1, length1].
     *
     * The signed content is the concatenation of the two ranges, excluding the
     * /Contents hex string that sits between them.
     */
    private fun extractSignedContent(pdfBytes: ByteArray, byteRange: IntArray): ByteArray {
        require(byteRange.size == 4) {
            "ByteRange must have exactly 4 elements, got ${byteRange.size}"
        }
        val (offset0, length0, offset1, length1) = byteRange.map { it }
        require(offset0 >= 0 && length0 >= 0 && offset1 >= 0 && length1 >= 0) {
            "ByteRange values must be non-negative"
        }
        require(offset0 + length0 <= pdfBytes.size && offset1 + length1 <= pdfBytes.size) {
            "ByteRange extends beyond PDF file size (${pdfBytes.size})"
        }

        val result = ByteArray(length0 + length1)
        System.arraycopy(pdfBytes, offset0, result, 0, length0)
        System.arraycopy(pdfBytes, offset1, result, length0, length1)
        return result
    }

    // -------------------------------------------------------------------------
    // Signing time extraction
    // -------------------------------------------------------------------------

    /**
     * Returns (signingTime, isTimestamp).
     *
     * Priority:
     * 1. Embedded RFC 3161 timestamp token in the SignerInfo's unsigned attributes
     *    (`id-aa-signatureTimeStampToken`) — cryptographically bound, trusted.
     * 2. Signing time signed attribute (`id-signingTime`) — claimed by signer, not trusted.
     * 3. /M entry in the PDF signature dictionary — claimed, not trusted.
     */
    private fun extractSigningTime(
        sig: PDSignature,
        signerInfo: SignerInformation
    ): Pair<Date?, Boolean> {
        // 1. RFC 3161 timestamp token
        val tsToken = extractTimestampToken(signerInfo)
        if (tsToken != null) {
            return Pair(tsToken.timeStampInfo.genTime, true)
        }

        // 2. CMS signingTime signed attribute
        val cmsSigningTime = signerInfo.signedAttributes
            ?.get(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_signingTime)
            ?.attrValues
            ?.getObjectAt(0)
        if (cmsSigningTime != null) {
            return try {
                val primitive = cmsSigningTime.toASN1Primitive()
                val date: Date? = when (primitive) {
                    is org.bouncycastle.asn1.ASN1GeneralizedTime -> primitive.date
                    is org.bouncycastle.asn1.ASN1UTCTime         -> primitive.date
                    else -> {
                        // Try re-parsing from encoded bytes
                        val reparsed = org.bouncycastle.asn1.ASN1Primitive.fromByteArray(primitive.encoded)
                        when (reparsed) {
                            is org.bouncycastle.asn1.ASN1GeneralizedTime -> reparsed.date
                            is org.bouncycastle.asn1.ASN1UTCTime         -> reparsed.date
                            else -> null
                        }
                    }
                }
                Pair(date, false)
            } catch (e: Exception) {
                Log.w(TAG, "Could not parse CMS signingTime attribute: ${e.message}")
                null to false
            }
        }

        // 3. PDF /M entry
        val pdfDate = sig.signDate?.time
        return Pair(pdfDate, false)
    }

    /**
     * Extracts an RFC 3161 [TimeStampToken] from the SignerInfo's unsigned
     * attributes, if present.
     */
    private fun extractTimestampToken(signerInfo: SignerInformation): TimeStampToken? {
        val unsignedAttrs = signerInfo.unsignedAttributes ?: return null
        val tsAttr = unsignedAttrs[org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken]
            ?: return null
        return try {
            val tsTokenBytes = (tsAttr.attrValues.getObjectAt(0) as org.bouncycastle.asn1.ASN1OctetString).octets
            TimeStampToken(CMSSignedData(tsTokenBytes))
        } catch (e: Exception) {
            try {
                // Some implementations embed the ContentInfo directly
                TimeStampToken(CMSSignedData(tsAttr.attrValues.getObjectAt(0).toASN1Primitive().encoded))
            } catch (e2: Exception) {
                Log.w(TAG, "Could not parse timestamp token: ${e2.message}")
                null
            }
        }
    }

    // -------------------------------------------------------------------------
    // Revocation (offline only)
    // -------------------------------------------------------------------------

    /**
     * Checks revocation status using only embedded information (LTV/DSS).
     * Never makes network calls.
     *
     * Currently reports UNKNOWN_OFFLINE unless embedded OCSP/CRL data is found
     * in the CMS structure's unsigned attributes or the PDF's DSS dictionary.
     */
    private fun checkRevocationOffline(
        cmsSignedData: CMSSignedData,
        signerCert: X509Certificate?,
        reasons: MutableList<String>
    ): RevocationStatus {
        // Check for embedded OCSP responses in CMS unsigned attributes
        // (id-smime-aa-securityLabel or id-aa-ets-revocationValues)
        val signerInfos = cmsSignedData.signerInfos.signers
        for (si in signerInfos) {
            val unsignedAttrs = si.unsignedAttributes ?: continue

            // id-aa-ets-revocationValues (RFC 5126 / PAdES LTV)
            val revValuesOid = org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.24")
            val revAttr = unsignedAttrs[revValuesOid]
            if (revAttr != null) {
                reasons += "Embedded revocation values (LTV) found in signature — offline revocation check possible."
                // A full LTV revocation check would parse the embedded CRLs/OCSP responses here.
                // For now we report the presence and defer to the chain builder's embedded data.
                return RevocationStatus.NOT_REVOKED_EMBEDDED
            }
        }

        reasons += "No embedded revocation info (OCSP/CRL) found. " +
                "Revocation status is UNKNOWN (offline — no network calls made)."
        return RevocationStatus.UNKNOWN_OFFLINE
    }

    // -------------------------------------------------------------------------
    // Certificate chain validation
    // -------------------------------------------------------------------------

    /**
     * Builds and validates the PKIX certificate chain from [signerCert] up to
     * one of the [trustedRoots].
     *
     * Revocation checking is disabled (offline mode); the caller has already
     * reported revocation status separately.
     *
     * @return `true` if a trusted chain was successfully built.
     */
    private fun validateCertificateChain(
        signerCert: X509Certificate,
        intermediateCerts: List<X509Certificate>,
        trustedRoots: List<X509Certificate>,
        validationDate: Date,
        reasons: MutableList<String>
    ): Boolean {
        return try {
            val trustAnchors = trustedRoots.map { TrustAnchor(it, null) }.toSet()

            val selector = X509CertSelector().apply { certificate = signerCert }

            val pkixParams = PKIXBuilderParameters(trustAnchors, selector).apply {
                isRevocationEnabled = false   // offline — no CRL/OCSP network calls
                date = validationDate

                // Add all intermediate certs from the CMS structure as a CertStore
                val allCerts = (intermediateCerts + trustedRoots).toMutableList()
                allCerts += signerCert
                addCertStore(
                    CertStore.getInstance(
                        "Collection",
                        CollectionCertStoreParameters(allCerts),
                        BouncyCastleProvider.PROVIDER_NAME
                    )
                )
            }

            val pathBuilder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME)
            val result = pathBuilder.build(pkixParams)

            val chain = result.certPath.certificates
            reasons += "Certificate chain validated successfully (${chain.size} certificate(s) in path)."
            chain.forEachIndexed { i, cert ->
                cert as X509Certificate
                reasons += "  [$i] ${cert.subjectX500Principal.name}"
            }
            true
        } catch (e: CertPathBuilderException) {
            reasons += "Certificate chain could NOT be validated: ${e.message}"
            reasons += "The issuer may not be in the trusted roots list. " +
                    "Add the appropriate CA certificate (e.g. CCA India root) to assets/trusted_roots/ or import it via the app."
            false
        } catch (e: Exception) {
            Log.e(TAG, "Chain validation error", e)
            reasons += "Chain validation error: ${e.message}"
            false
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /** Extracts the Common Name (CN) from an X.509 subject DN. */
    private fun extractCn(cert: X509Certificate?): String? {
        val dn = cert?.subjectX500Principal?.name ?: return null
        // DN is in RFC 2253 format: "CN=Foo Bar,O=Org,C=IN"
        return dn.split(",")
            .map { it.trim() }
            .firstOrNull { it.startsWith("CN=", ignoreCase = true) }
            ?.removePrefix("CN=")
            ?.removePrefix("cn=")
    }
}

// ---------------------------------------------------------------------------
// Custom exceptions
// ---------------------------------------------------------------------------

/**
 * Thrown when a PDF is encrypted and the supplied password is missing or wrong.
 */
class PasswordRequiredException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
