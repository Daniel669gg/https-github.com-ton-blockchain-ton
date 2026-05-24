package io.ghost.security

import com.intellij.codeInspection.*
import com.intellij.notification.*
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.*
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.progress.*
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.openapi.wm.*
import com.intellij.psi.PsiFile
import com.intellij.util.concurrency.AppExecutorUtil
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit


// ── Data models ───────────────────────────────────────────────────────────────

@Serializable
data class GhostFinding(
    val rule_id: String = "",
    val severity: String = "MEDIUM",
    val message: String = "",
    val description: String = "",
    val file: String = "",
    val line: Int = 1,
    val column: Int = 1,
    val cwe: String = "",
    val owasp: String = "",
    val confidence: Double = 0.8,
    val recommendation: String = "",
    val evidence: String = "",
    val priority: String = "",
)

data class ScanResult(
    val findings: List<GhostFinding>,
    val severityCounts: Map<String, Int>,
    val scanId: String?,
)

// ── Settings ──────────────────────────────────────────────────────────────────

@State(
    name = "GhostSecuritySettings",
    storages = [Storage("GhostSecurity.xml")]
)
class GhostSettings : PersistentStateComponent<GhostSettings.State> {

    data class State(
        var serverUrl: String = "http://localhost:8000",
        var apiKey: String = "",
        var scanOnSave: Boolean = true,
        var scanOnType: Boolean = false,
        var minSeverity: String = "MEDIUM",
        var autoFix: Boolean = true,
        var showInlineHints: Boolean = true,
    )

    private var state = State()

    override fun getState(): State = state
    override fun loadState(state: State) { this.state = state }

    companion object {
        fun getInstance(): GhostSettings =
            ApplicationManager.getApplication().getService(GhostSettings::class.java)
    }

    val serverUrl get() = state.serverUrl
    val apiKey    get() = state.apiKey
    val minSeverity get() = state.minSeverity
    val scanOnSave  get() = state.scanOnSave
    val autoFix     get() = state.autoFix
}


// ── API Client ────────────────────────────────────────────────────────────────

object GhostApiClient {

    private val severityOrder = mapOf("CRITICAL" to 4, "HIGH" to 3, "MEDIUM" to 2, "LOW" to 1, "INFO" to 0)
    private val json = Json { ignoreUnknownKeys = true }

    fun isAlive(): Boolean {
        return try {
            val url = URL("${GhostSettings.getInstance().serverUrl}/health")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 2000
            conn.readTimeout    = 2000
            conn.responseCode == 200
        } catch (e: Exception) { false }
    }

    fun scanInline(filePath: String, content: String, language: String): ScanResult? {
        val settings = GhostSettings.getInstance()
        return try {
            val url  = URL("${settings.serverUrl}/api/scan/inline")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput      = true
            conn.connectTimeout = 30_000
            conn.readTimeout    = 30_000
            conn.setRequestProperty("Content-Type", "application/json")
            if (settings.apiKey.isNotEmpty())
                conn.setRequestProperty("Authorization", "Bearer ${settings.apiKey}")

            val body = """{"path":"$filePath","content":${escapeJson(content)},"language":"$language"}"""
            conn.outputStream.write(body.toByteArray())

            if (conn.responseCode != 200) return null
            val response = conn.inputStream.bufferedReader().readText()
            parseResult(response)
        } catch (e: Exception) { null }
    }

    fun explainFinding(finding: GhostFinding): String? {
        val settings = GhostSettings.getInstance()
        return try {
            val url  = URL("${settings.serverUrl}/api/v2/ollama/explain")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput      = true
            conn.connectTimeout = 60_000
            conn.readTimeout    = 60_000
            conn.setRequestProperty("Content-Type", "application/json")
            val findingJson = """{"rule_id":"${finding.rule_id}","severity":"${finding.severity}","message":"${finding.message}","cwe":"${finding.cwe}","file":"${finding.file}","line":${finding.line}}"""
            val body = """{"finding":$findingJson}"""
            conn.outputStream.write(body.toByteArray())
            if (conn.responseCode != 200) return null
            val resp = json.parseToJsonElement(conn.inputStream.bufferedReader().readText())
            resp.jsonObject["explanation"]?.jsonPrimitive?.content
        } catch (e: Exception) { null }
    }

    fun generateFix(finding: GhostFinding, codeContext: String): String? {
        val settings = GhostSettings.getInstance()
        return try {
            val url  = URL("${settings.serverUrl}/api/v2/ollama/remediate")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput      = true
            conn.connectTimeout = 90_000
            conn.readTimeout    = 90_000
            conn.setRequestProperty("Content-Type", "application/json")
            val findingJson = """{"rule_id":"${finding.rule_id}","severity":"${finding.severity}","message":"${finding.message}","cwe":"${finding.cwe}"}"""
            val body = """{"finding":$findingJson,"code_context":${escapeJson(codeContext)}}"""
            conn.outputStream.write(body.toByteArray())
            if (conn.responseCode != 200) return null
            val resp = json.parseToJsonElement(conn.inputStream.bufferedReader().readText())
            resp.jsonObject["remediation"]?.jsonPrimitive?.content
        } catch (e: Exception) { null }
    }

    private fun parseResult(response: String): ScanResult? {
        return try {
            val root     = json.parseToJsonElement(response).jsonObject
            val findings = root["findings"]?.jsonArray?.map {
                json.decodeFromJsonElement<GhostFinding>(it)
            } ?: emptyList()
            val counts   = root["severity_counts"]?.jsonObject
                ?.mapValues { it.value.jsonPrimitive.int } ?: emptyMap()
            val scanId   = root["scan_id"]?.jsonPrimitive?.contentOrNull
            val settings = GhostSettings.getInstance()
            val minIdx   = severityOrder[settings.minSeverity] ?: 2
            val filtered = findings.filter { (severityOrder[it.severity] ?: 0) >= minIdx }
            ScanResult(filtered, counts, scanId)
        } catch (e: Exception) { null }
    }

    private fun escapeJson(s: String) =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
               .replace("\n", "\\n").replace("\r", "\\r").take(4000) + "\""
}


// ── Base Inspection ───────────────────────────────────────────────────────────

abstract class GhostBaseInspection : LocalInspectionTool() {

    protected fun runScan(file: PsiFile, holder: ProblemsHolder) {
        if (!GhostApiClient.isAlive()) return
        val content  = file.text ?: return
        val language = detectLanguage(file)
        val result   = GhostApiClient.scanInline(file.virtualFile?.path ?: "", content, language) ?: return

        for (finding in result.findings) {
            val lineIdx = finding.line - 1
            val lines   = content.split("\n")
            if (lineIdx < 0 || lineIdx >= lines.size) continue

            val offset = lines.take(lineIdx).sumOf { it.length + 1 }
            val lineLen = lines[lineIdx].length
            val range   = TextRange(offset, offset + lineLen)

            val severity = when (finding.severity) {
                "CRITICAL", "HIGH" -> ProblemHighlightType.GENERIC_ERROR
                "MEDIUM"           -> ProblemHighlightType.WARNING
                else               -> ProblemHighlightType.WEAK_WARNING
            }
            holder.registerProblem(
                file,
                range,
                "[Ghost:${finding.severity}] ${finding.message} (${finding.rule_id})",
                severity,
                GhostExplainFix(finding),
                GhostFixAction(finding),
            )
        }
    }

    private fun detectLanguage(file: PsiFile): String = when (file.language.id.lowercase()) {
        "python"     -> "python"
        "java"       -> "java"
        "kotlin"     -> "kotlin"
        "javascript" -> "javascript"
        "typescript" -> "typescript"
        "go"         -> "go"
        else         -> file.virtualFile?.extension?.lowercase() ?: "unknown"
    }
}


// ── Quick Fix Actions ─────────────────────────────────────────────────────────

class GhostExplainFix(private val finding: GhostFinding) : LocalQuickFix {
    override fun getName()       = "Ghost: Explain this finding (AI)"
    override fun getFamilyName() = "Ghost Security"

    override fun applyFix(project: Project, descriptor: ProblemDescriptor) {
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Ghost: Getting AI explanation...") {
            override fun run(indicator: ProgressIndicator) {
                val explanation = GhostApiClient.explainFinding(finding)
                    ?: "Explanation unavailable (check Ghost server connection)"
                ApplicationManager.getApplication().invokeLater {
                    NotificationGroupManager.getInstance()
                        .getNotificationGroup("Ghost Security")
                        .createNotification(
                            "[${finding.severity}] ${finding.rule_id}",
                            explanation.take(500),
                            NotificationType.INFORMATION,
                        ).notify(project)
                }
            }
        })
    }
}

class GhostFixAction(private val finding: GhostFinding) : LocalQuickFix {
    override fun getName()       = "Ghost: Generate AI Fix"
    override fun getFamilyName() = "Ghost Security"

    override fun applyFix(project: Project, descriptor: ProblemDescriptor) {
        val context = descriptor.psiElement?.containingFile?.text?.take(2000) ?: ""
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Ghost: Generating fix...") {
            override fun run(indicator: ProgressIndicator) {
                val fix = GhostApiClient.generateFix(finding, context)
                    ?: "Fix generation unavailable (requires Ollama/OpenAI)"
                ApplicationManager.getApplication().invokeLater {
                    NotificationGroupManager.getInstance()
                        .getNotificationGroup("Ghost Security")
                        .createNotification(
                            "Ghost Fix: ${finding.rule_id}",
                            fix.take(800),
                            NotificationType.INFORMATION,
                        ).notify(project)
                }
            }
        })
    }
}


// ── Language-specific inspections ─────────────────────────────────────────────

class GhostPythonInspection : GhostBaseInspection() {
    override fun getDisplayName() = "Ghost Security: Python vulnerabilities"
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor> {
        val holder = ProblemsHolder(manager, file, isOnTheFly)
        if (file.name.endsWith(".py")) runScan(file, holder)
        return holder.resultsArray
    }
}

class GhostJavaInspection : GhostBaseInspection() {
    override fun getDisplayName() = "Ghost Security: Java vulnerabilities"
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor> {
        val holder = ProblemsHolder(manager, file, isOnTheFly)
        if (file.name.endsWith(".java")) runScan(file, holder)
        return holder.resultsArray
    }
}

class GhostKotlinInspection : GhostBaseInspection() {
    override fun getDisplayName() = "Ghost Security: Kotlin vulnerabilities"
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor> {
        val holder = ProblemsHolder(manager, file, isOnTheFly)
        if (file.name.endsWith(".kt")) runScan(file, holder)
        return holder.resultsArray
    }
}
