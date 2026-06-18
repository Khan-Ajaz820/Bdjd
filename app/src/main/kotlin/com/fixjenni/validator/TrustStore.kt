package com.fixjenni.validator

import android.content.Context
import android.net.Uri
import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Manages trusted root CA certificates from two sources:
 *
 * 1. **Bundled assets** – every `.cer`, `.crt`, `.pem`, or `.der` file found
 *    under `assets/trusted_roots/` at build time.
 * 2. **User-imported roots** – certificates the user picks at runtime; stored
 *    in the app's private internal storage (`files/user_trusted_roots/`).
 *
 * Both sets are merged on every call to [getTrustedCertificates].
 *
 * No network calls are ever made.
 */
class TrustStore(private val context: Context) {

    companion object {
        private const val TAG = "TrustStore"
        private const val ASSET_DIR = "trusted_roots"
        private const val USER_ROOTS_DIR = "user_trusted_roots"
        private val CERT_EXTENSIONS = setOf("cer", "crt", "pem", "der")
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Returns the merged set of trusted [X509Certificate]s from both bundled
     * assets and user-imported roots.  Never throws; bad files are skipped and
     * logged.
     */
    fun getTrustedCertificates(): List<X509Certificate> {
        val certs = mutableListOf<X509Certificate>()
        certs += loadBundledAssets()
        certs += loadUserImportedRoots()
        Log.d(TAG, "Total trusted roots loaded: ${certs.size}")
        return certs
    }

    /**
     * Imports a certificate from the given [uri] (obtained via SAF
     * ACTION_OPEN_DOCUMENT) and persists it to internal storage so it is
     * available on future validations.
     *
     * @return the imported [X509Certificate] on success, or `null` on failure.
     */
    fun importCertificate(uri: Uri): X509Certificate? {
        return try {
            val inputStream = context.contentResolver.openInputStream(uri)
                ?: return null
            val cert = parseCertificate(inputStream) ?: return null

            // Persist to internal storage
            val dir = getUserRootsDir()
            // Use the certificate's serial number + subject hash as filename
            val filename = "${cert.serialNumber}_${cert.subjectX500Principal.name.hashCode()}.der"
            val outFile = File(dir, filename)
            outFile.outputStream().use { out ->
                out.write(cert.encoded)
            }
            Log.i(TAG, "Imported trusted root: ${cert.subjectX500Principal.name}")
            cert
        } catch (e: Exception) {
            Log.e(TAG, "Failed to import certificate from $uri", e)
            null
        }
    }

    /**
     * Returns the list of user-imported root certificates currently stored in
     * internal storage.
     */
    fun listUserImportedRoots(): List<X509Certificate> = loadUserImportedRoots()

    /**
     * Deletes all user-imported root certificates from internal storage.
     */
    fun clearUserImportedRoots() {
        getUserRootsDir().listFiles()?.forEach { it.delete() }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private fun loadBundledAssets(): List<X509Certificate> {
        val certs = mutableListOf<X509Certificate>()
        try {
            val files = context.assets.list(ASSET_DIR) ?: return certs
            for (filename in files) {
                val ext = filename.substringAfterLast('.', "").lowercase()
                if (ext !in CERT_EXTENSIONS) continue
                try {
                    val stream = context.assets.open("$ASSET_DIR/$filename")
                    val cert = parseCertificate(stream)
                    if (cert != null) {
                        certs += cert
                        Log.d(TAG, "Loaded bundled root: ${cert.subjectX500Principal.name} [$filename]")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Skipping bundled asset $filename: ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not list bundled assets/$ASSET_DIR: ${e.message}")
        }
        return certs
    }

    private fun loadUserImportedRoots(): List<X509Certificate> {
        val certs = mutableListOf<X509Certificate>()
        val dir = getUserRootsDir()
        dir.listFiles()?.forEach { file ->
            try {
                val cert = parseCertificate(file.inputStream())
                if (cert != null) {
                    certs += cert
                    Log.d(TAG, "Loaded user root: ${cert.subjectX500Principal.name} [${file.name}]")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Skipping user root ${file.name}: ${e.message}")
            }
        }
        return certs
    }

    private fun getUserRootsDir(): File {
        val dir = File(context.filesDir, USER_ROOTS_DIR)
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    /**
     * Attempts to parse an [X509Certificate] from [stream].
     * Handles DER, PEM (single or chain — takes the first cert), and raw DER.
     */
    private fun parseCertificate(stream: InputStream): X509Certificate? {
        val bytes = stream.use { it.readBytes() }
        val factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)

        // Try PEM / DER via CertificateFactory (handles both transparently)
        return try {
            factory.generateCertificate(bytes.inputStream()) as? X509Certificate
        } catch (e: Exception) {
            // Some PEM files have headers/footers that confuse the factory;
            // strip them and try again as raw DER.
            try {
                val stripped = stripPemHeaders(bytes)
                factory.generateCertificate(stripped.inputStream()) as? X509Certificate
            } catch (e2: Exception) {
                Log.w(TAG, "Could not parse certificate: ${e2.message}")
                null
            }
        }
    }

    /**
     * Decodes a PEM-encoded certificate (strips `-----BEGIN/END CERTIFICATE-----`
     * headers and base64-decodes the body) to raw DER bytes.
     */
    private fun stripPemHeaders(bytes: ByteArray): ByteArray {
        val text = String(bytes, Charsets.US_ASCII)
        val body = text.lines()
            .filter { !it.startsWith("-----") && it.isNotBlank() }
            .joinToString("")
        return android.util.Base64.decode(body, android.util.Base64.DEFAULT)
    }
}
