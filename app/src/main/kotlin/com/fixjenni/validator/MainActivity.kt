package com.fixjenni.validator

import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.text.SimpleDateFormat
import java.util.Locale

class MainActivity : AppCompatActivity() {

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------
    private lateinit var btnPickPdf: Button
    private lateinit var btnImportCert: Button
    private lateinit var btnClearResults: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var tvResults: TextView
    private lateinit var scrollView: ScrollView

    // -------------------------------------------------------------------------
    // Core components
    // -------------------------------------------------------------------------
    private lateinit var trustStore: TrustStore
    private lateinit var validator: PdfSignatureValidator

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)

    // -------------------------------------------------------------------------
    // SAF launchers
    // -------------------------------------------------------------------------

    /** Launches the system file picker for PDF files. */
    private val pickPdfLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            validatePdf(uri)
        }
    }

    /** Launches the system file picker for certificate files. */
    private val importCertLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            importTrustedRoot(uri)
        }
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Register Bouncy Castle as the first provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        // Initialise PDFBox resource loader (required for font/colour resources)
        PDFBoxResourceLoader.init(applicationContext)

        setContentView(R.layout.activity_main)

        btnPickPdf    = findViewById(R.id.btnPickPdf)
        btnImportCert = findViewById(R.id.btnImportCert)
        btnClearResults = findViewById(R.id.btnClearResults)
        progressBar   = findViewById(R.id.progressBar)
        tvResults     = findViewById(R.id.tvResults)
        scrollView    = findViewById(R.id.scrollView)

        trustStore = TrustStore(this)
        validator  = PdfSignatureValidator(trustStore)

        btnPickPdf.setOnClickListener {
            pickPdfLauncher.launch(arrayOf("application/pdf"))
        }

        btnImportCert.setOnClickListener {
            importCertLauncher.launch(
                arrayOf(
                    "application/x-x509-ca-cert",
                    "application/x-pem-file",
                    "application/pkix-cert",
                    "*/*"   // fallback — some file managers don't honour MIME types
                )
            )
        }

        btnClearResults.setOnClickListener {
            tvResults.text = getString(R.string.hint_pick_pdf)
        }

        // Handle VIEW intent (e.g. opened from a file manager)
        if (intent?.action == Intent.ACTION_VIEW) {
            intent.data?.let { validatePdf(it) }
        }
    }

    // -------------------------------------------------------------------------
    // PDF validation
    // -------------------------------------------------------------------------

    private fun validatePdf(uri: Uri) {
        setLoading(true)
        appendResult("─────────────────────────────────────────")
        appendResult("📄 Validating: ${uri.lastPathSegment ?: uri.toString()}")
        appendResult("─────────────────────────────────────────")

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val stream = contentResolver.openInputStream(uri)
                        ?: return@runCatching ValidationOutcome.Error("Cannot open file.")
                    stream.use { validator.validate(it) }
                        .let { ValidationOutcome.Success(it) }
                }
            }

            setLoading(false)

            result.fold(
                onSuccess = { outcome ->
                    when (outcome) {
                        is ValidationOutcome.Success -> displayResults(outcome.results)
                        is ValidationOutcome.Error   -> appendResult("❌ Error: ${outcome.message}")
                    }
                },
                onFailure = { throwable ->
                    when (throwable) {
                        is PasswordRequiredException -> promptForPassword(uri)
                        else -> appendResult("❌ Unexpected error: ${throwable.message}")
                    }
                }
            )
        }
    }

    private fun validatePdfWithPassword(uri: Uri, password: String) {
        setLoading(true)
        appendResult("🔑 Retrying with password…")

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val stream = contentResolver.openInputStream(uri)
                        ?: return@runCatching ValidationOutcome.Error("Cannot open file.")
                    stream.use { validator.validate(it, password) }
                        .let { ValidationOutcome.Success(it) }
                }
            }

            setLoading(false)

            result.fold(
                onSuccess = { outcome ->
                    when (outcome) {
                        is ValidationOutcome.Success -> displayResults(outcome.results)
                        is ValidationOutcome.Error   -> appendResult("❌ Error: ${outcome.message}")
                    }
                },
                onFailure = { throwable ->
                    when (throwable) {
                        is PasswordRequiredException ->
                            appendResult("❌ Wrong password — please try again.")
                                .also { promptForPassword(uri) }
                        else -> appendResult("❌ Unexpected error: ${throwable.message}")
                    }
                }
            )
        }
    }

    private fun displayResults(results: List<SignatureResult>) {
        if (results.isEmpty()) {
            appendResult("ℹ️  No digital signatures found in this PDF.")
            return
        }

        appendResult("Found ${results.size} signature(s):\n")

        results.forEachIndexed { index, sig ->
            val statusIcon = when (sig.status) {
                SignatureStatus.VALID                -> "✅"
                SignatureStatus.INVALID              -> "❌"
                SignatureStatus.INTACT_BUT_UNTRUSTED -> "⚠️"
                SignatureStatus.INTACT_CERT_EXPIRED  -> "⚠️"
                SignatureStatus.ERROR                -> "🔴"
            }

            val sb = StringBuilder()
            sb.appendLine("$statusIcon Signature ${index + 1}: ${sig.fieldName}")
            sb.appendLine("   Status      : ${sig.status}")
            sb.appendLine("   Signer      : ${sig.signerName ?: "Unknown"}")
            sb.appendLine("   Subject DN  : ${sig.signerDn ?: "N/A"}")
            sb.appendLine("   Issuer      : ${sig.issuerDn ?: "N/A"}")
            sb.appendLine("   Serial      : ${sig.serialNumber ?: "N/A"}")

            val timeStr = sig.signingTime?.let { dateFormat.format(it) } ?: "N/A"
            val timeSource = if (sig.signingTimeIsTimestamp) " [RFC 3161 TS]" else " [claimed]"
            sb.appendLine("   Signing Time: $timeStr$timeSource")

            sb.appendLine("   Revocation  : ${sig.revocationStatus}")
            sb.appendLine("   Chain depth : ${sig.certificateChain.size} cert(s)")
            sb.appendLine()
            sb.appendLine("   Details:")
            sig.reasons.forEach { reason ->
                sb.appendLine("     • $reason")
            }

            appendResult(sb.toString())
        }
    }

    // -------------------------------------------------------------------------
    // Certificate import
    // -------------------------------------------------------------------------

    private fun importTrustedRoot(uri: Uri) {
        lifecycleScope.launch {
            val cert = withContext(Dispatchers.IO) {
                trustStore.importCertificate(uri)
            }
            if (cert != null) {
                val cn = cert.subjectX500Principal.name
                    .split(",").firstOrNull { it.trim().startsWith("CN=", ignoreCase = true) }
                    ?.substringAfter("=") ?: cert.subjectX500Principal.name
                appendResult("✅ Trusted root imported: $cn")
            } else {
                appendResult("❌ Failed to import certificate. Make sure the file is a valid .cer/.crt/.pem/.der certificate.")
            }
        }
    }

    // -------------------------------------------------------------------------
    // Password dialog
    // -------------------------------------------------------------------------

    private fun promptForPassword(uri: Uri) {
        val input = EditText(this).apply {
            hint = "PDF password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                    android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        AlertDialog.Builder(this)
            .setTitle("Password Required")
            .setMessage("This PDF is encrypted. Please enter the password to open it.")
            .setView(input)
            .setPositiveButton("Validate") { _, _ ->
                val password = input.text.toString()
                if (password.isNotEmpty()) {
                    validatePdfWithPassword(uri, password)
                } else {
                    appendResult("❌ No password entered.")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // -------------------------------------------------------------------------
    // UI helpers
    // -------------------------------------------------------------------------

    private fun setLoading(loading: Boolean) {
        progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        btnPickPdf.isEnabled    = !loading
        btnImportCert.isEnabled = !loading
    }

    private fun appendResult(text: String): Unit {
        val current = tvResults.text.toString()
        val separator = if (current == getString(R.string.hint_pick_pdf) || current.isEmpty()) "" else "\n"
        tvResults.text = if (current == getString(R.string.hint_pick_pdf)) text else "$current$separator$text"
        // Scroll to bottom
        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
    }

    // -------------------------------------------------------------------------
    // Internal sealed class for coroutine results
    // -------------------------------------------------------------------------

    private sealed class ValidationOutcome {
        data class Success(val results: List<SignatureResult>) : ValidationOutcome()
        data class Error(val message: String) : ValidationOutcome()
    }
}
