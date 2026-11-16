Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
let node_crypto = require("node:crypto");
let node_fs = require("node:fs");
let node_path = require("node:path");
// ../castov-core/dist/audit/types.js
const ALL_RULES_METADATA = {
	"CAS-001": {
		id: "CAS-001",
		title: "Hardcoded Secret in Server Config",
		severity: "critical",
		whyItMatters: "Exposes live credentials directly in plain text configuration files.",
		suggestedFix: "Keep secrets outside configuration files and git, and use the client's documented variable reference mechanism.",
		securitySeverity: 9.5
	},
	"CAS-002": {
		id: "CAS-002",
		title: "Unpinned Runtime Launcher",
		severity: "medium",
		whyItMatters: "Executing packages or containers without explicit version pinning allows automatic pulling of compromised or untested releases.",
		suggestedFix: "Pin exact package versions or immutable container tags/digests.",
		securitySeverity: 5.5
	},
	"CAS-003": {
		id: "CAS-003",
		title: "Shell Wrapper or Embedded Script",
		severity: "high",
		whyItMatters: "Running tools through a shell command string introduces arbitrary command injection and shell escape vulnerabilities.",
		suggestedFix: "Invoke target binaries directly as executable command without shell wrappers (-c / -Command).",
		securitySeverity: 8.5
	},
	"CAS-004": {
		id: "CAS-004",
		title: "Remote Server Security & Data Flow",
		severity: "high",
		whyItMatters: "Unencrypted or unauthenticated remote endpoints expose prompts and tool payloads to interception.",
		suggestedFix: "Use HTTPS with explicit authentication headers for all remote servers.",
		securitySeverity: 7.5
	},
	"CAS-005": {
		id: "CAS-005",
		title: "Broad Filesystem Scope",
		severity: "high",
		whyItMatters: "Granting root or user home directory access exposes private SSH keys, cloud tokens, and system files.",
		suggestedFix: "Restrict tool filesystem arguments to specific project directories.",
		securitySeverity: 8
	},
	"CAS-006": {
		id: "CAS-006",
		title: "Docker Container Risks",
		severity: "critical",
		whyItMatters: "Privileged containers or host docker.sock bindings provide root-equivalent privilege escalation over the host.",
		suggestedFix: "Avoid --privileged mode and docker.sock volume mounts.",
		securitySeverity: 9.8
	},
	"CAS-007": {
		id: "CAS-007",
		title: "Auto-Approve / Always-Allow Permissions",
		severity: "high",
		whyItMatters: "Automatically approving destructive tool execution bypasses human confirmation.",
		suggestedFix: "Enforce interactive user approval for file modifications and shell execution.",
		securitySeverity: 7.8
	},
	"CAS-008": {
		id: "CAS-008",
		title: ".env Unprotected from AI Context or Unrespected .claudeignore",
		severity: "medium",
		whyItMatters: "Plaintext .env files without a verified agent block (Cursor .cursorignore or Claude Code permissions.deny in .claude/settings.json) can be read into LLM context. Note that .claudeignore is not respected by Claude Code.",
		suggestedFix: "Add permissions.deny Read(./.env) / Read(./.env.*) in .claude/settings.json for Claude Code, add .env* to .cursorignore for Cursor, and keep secrets outside the project directory.",
		securitySeverity: 5.5
	},
	"CAS-009": {
		id: "CAS-009",
		title: "Literal Secret in Config or Git-Tracked/Unignored .env",
		severity: "high",
		whyItMatters: "Hardcoded secrets in environment/config files or .env files tracked/unignored by Git risk leaking credentials into version history.",
		suggestedFix: "Add .env* to .gitignore, remove tracked .env files with git rm --cached, and replace literal secrets with placeholders.",
		securitySeverity: 8.5
	},
	"CAS-010": {
		id: "CAS-010",
		title: "Duplicate or Conflicting MCP Server Definition",
		severity: "low",
		whyItMatters: "Duplicate server names across project and user scopes lead to ambiguous tool dispatch and unexpected overrides.",
		suggestedFix: "Rename conflicting MCP servers to ensure unique identifiers across scopes.",
		securitySeverity: 3
	},
	"CAS-011": {
		id: "CAS-011",
		title: "MCP Server Baseline Drift (Potential Rug Pull)",
		severity: "high",
		whyItMatters: "A server's executable command, arguments, endpoint URL, or presence changed relative to the approved security baseline.",
		suggestedFix: "Review the server configuration diff against the approved baseline before running the tool.",
		securitySeverity: 8.2
	},
	"CAS-012": {
		id: "CAS-012",
		title: "Unparseable Configuration File",
		severity: "info",
		whyItMatters: "Configuration file contains syntax errors or invalid formatting preventing tool analysis and loading.",
		suggestedFix: "Fix JSON syntax errors, ensure balanced brackets and valid quotes.",
		securitySeverity: 2
	},
	"CAS-013": {
		id: "CAS-013",
		title: "Insecure or Deprecated Transport",
		severity: "medium",
		whyItMatters: "Using unencrypted or deprecated transport protocols allows eavesdropping on agent-tool communications.",
		suggestedFix: "Use standard stdio or TLS-secured HTTPS/WSS transport protocols.",
		securitySeverity: 6
	},
	"CAS-014": {
		id: "CAS-014",
		title: "Missing or Unresolvable Command Binary",
		severity: "low",
		whyItMatters: "The command path specified for the MCP server does not exist on disk, causing startup failures.",
		suggestedFix: "Ensure the target executable path exists and is built before launching the MCP server.",
		securitySeverity: 2.5
	},
	"CAS-015": {
		id: "CAS-015",
		title: "Excessive Environment Variable Pass-Through",
		severity: "low",
		whyItMatters: "Passing wildcard or excessive environment variables to child tools violates least privilege and increases secret exposure surface.",
		suggestedFix: "Explicitly declare only the minimal required environment variables.",
		securitySeverity: 3.5
	},
	"CAS-016": {
		id: "CAS-016",
		title: "Hidden Unicode/Bidi Characters or Override Heuristics in AI Rules",
		severity: "high",
		whyItMatters: "Zero-width, bidirectional control, or tag characters and prompt override directives in AI rule files can hide malicious instructions from human reviewers.",
		suggestedFix: "Strip all hidden Unicode/Bidi/Tag characters and remove unsafe guardrail bypass instructions.",
		securitySeverity: 8.8
	}
};
// ../castov-core/dist/audit/secrets.js
/**
* Secret Detection & Strict Masking Engine.
*
* Masking Rules:
* - If length < 16: masked completely as `… (${len} chars)`
* - If length >= 16: first 4 chars + `… (${len} chars)`
*
* Contextual Safe-Value Rules (isSafeOrVariableReference):
* - Variable references must match the ENTIRE value (no partial substring bypass).
* - If a variable reference uses default fallback syntax `${VAR:-default}`, the `default` part
*   is recursively analyzed as a normal value (so a literal secret in `default` is NOT safe and triggers a finding).
* - 40/64-char hex strings are NEVER safe if the key/context contains SECRET, KEY, TOKEN, PASSWORD, PASS, CREDENTIAL, or AUTH;
*   they are only safe in revision/commit/sha/digest/hash contexts or Docker @sha256: digests.
* - UUIDs are NEVER safe if the key/context contains SECRET, KEY, TOKEN, PASSWORD, PASS, CREDENTIAL, or AUTH.
* - localhost URLs are inspected for userinfo and query parameters; any secret-like query parameter or userinfo marks it unsafe.
*/
const SENSITIVE_KEY_REGEX = /(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL|AUTH)/i;
const SAFE_HASH_CONTEXT_REGEX = /(?:revision|commit|sha|digest|hash|checksum)/i;
const SAFE_UUID_CONTEXT_REGEX = /(?:^id$|_id$|^uuid$|session|trace|request|correlation|workspace|project|tenant|org|user_id|client_id)/i;
/**
* Strict Masking Utility:
* - If length < 16: completely masked as `… (${len} chars)`
* - If length >= 16: first 4 chars + `…` + `(${len} chars)`
*/
function maskSecret(val) {
	if (!val) return "";
	const len = val.length;
	if (len < 16) return `… (${len} chars)`;
	return `${val.slice(0, 4)}… (${len} chars)`;
}
/**
* Extract the default fallback value from a `${VAR:-default}` or `${env:VAR:-default}` expression, if present.
* Returns null if the string is not a `${...:-...}` expression.
*/
function extractDefaultFromVarSubstitution(val) {
	if (!val || typeof val !== "string") return null;
	const trimmed = val.trim();
	const match = /^(?:(?:Bearer|Basic)\s+)?\$\{([A-Za-z0-9_.:/]+):-([\s\S]*)\}$/i.exec(trimmed);
	if (!match) return null;
	return {
		varName: match[1],
		defaultValue: match[2]
	};
}
/**
* Checks whether a value is a pure, full-string environment/input variable reference WITHOUT a literal secret default,
* or an explicit non-secret placeholder.
* Does NOT allow partial matches mixed with literal secrets (e.g., "Bearer real_secret ${X}").
* For `${VAR:-default}`, returns true ONLY if `default` is empty or a safe placeholder/variable reference.
*/
function isPureVariableReferenceOrPlaceholder(val, keyOrContext) {
	if (!val || typeof val !== "string") return true;
	const trimmed = val.trim();
	if (!trimmed) return true;
	const withDefault = extractDefaultFromVarSubstitution(trimmed);
	if (withDefault !== null) {
		const defVal = withDefault.defaultValue.trim();
		if (!defVal) return true;
		return isSafeOrVariableReference(defVal, keyOrContext || withDefault.varName);
	}
	if (/^(?:(?:Bearer|Basic)\s+)?\$\{[A-Za-z0-9_.:/]+\}$/i.test(trimmed)) return true;
	if (/^(?:(?:Bearer|Basic)\s+)?\$[A-Za-z_][A-Za-z0-9_]*$/i.test(trimmed)) return true;
	if (/^(?:(?:Bearer|Basic)\s+)?%[A-Za-z_][A-Za-z0-9_]*%$/i.test(trimmed)) return true;
	if (/^<[^>]+>$/.test(trimmed)) return true;
	if (/^(?:placeholder|your[-_]?[a-z0-9_]*[-_]?here|your[-_]?key|todo|changeme|xxx+|\*{4,})$/i.test(trimmed)) return true;
	return false;
}
/**
* Context-aware check for safe non-secret values:
* - Full-string variable references (${env:X}, ${input:X}, ${X}, $VAR, %VAR%), with `${VAR:-default}` inspecting `default`
* - Docker image @sha256:<64-hex> digests
* - 40/64-char hex ONLY when key/context is revision/commit/sha/digest/hash and NOT a sensitive key name
* - UUIDs ONLY when key/context does NOT contain SECRET/KEY/TOKEN/PASSWORD/PASS/CREDENTIAL/AUTH
* - Localhost URLs ONLY when they have no userinfo and no secret-like query parameters
*/
function isSafeOrVariableReference(val, keyOrContext) {
	if (!val || typeof val !== "string") return true;
	const trimmed = val.trim();
	if (!trimmed) return true;
	const ctx = (keyOrContext || "").trim();
	const isSensitiveKey = ctx.length > 0 && SENSITIVE_KEY_REGEX.test(ctx);
	const withDefault = extractDefaultFromVarSubstitution(trimmed);
	if (withDefault !== null) {
		const defVal = withDefault.defaultValue.trim();
		if (!defVal) return true;
		const effectiveCtx = ctx || withDefault.varName;
		if (matchesKnownProviderPattern(defVal) !== null) return false;
		return isSafeOrVariableReference(defVal, effectiveCtx);
	}
	if (isPureVariableReferenceOrPlaceholder(trimmed, ctx)) return true;
	if (!isSensitiveKey && /^(?:[a-z0-9._/-]+)?@sha256:[0-9a-f]{64}$/i.test(trimmed)) return true;
	if (/^[0-9a-f]{40}$/i.test(trimmed) || /^[0-9a-f]{64}$/i.test(trimmed)) {
		if (isSensitiveKey) return false;
		if (ctx.length > 0 && SAFE_HASH_CONTEXT_REGEX.test(ctx)) return true;
		return false;
	}
	if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
		if (isSensitiveKey) return false;
		if (!ctx || SAFE_UUID_CONTEXT_REGEX.test(ctx) || SAFE_HASH_CONTEXT_REGEX.test(ctx)) return true;
		return false;
	}
	if (/^(?:https?|wss?):\/\/(?:localhost|127\.0\.0\.1|\[::1\]|::1)(?::\d+)?(?:\/.*)?$/i.test(trimmed)) try {
		const parsed = new URL(trimmed);
		if (parsed.username || parsed.password) return false;
		for (const [qKey, qVal] of parsed.searchParams.entries()) {
			if (!qVal || isPureVariableReferenceOrPlaceholder(qVal, qKey)) continue;
			if (SENSITIVE_KEY_REGEX.test(qKey)) return false;
			if (matchesKnownProviderPattern(qVal) !== null) return false;
		}
		return true;
	} catch {
		return false;
	}
	return false;
}
/**
* Known provider and structural secret patterns
*/
const SECRET_PATTERNS = [
	{
		name: "AWS Access Key ID",
		provider: "AWS",
		regex: /\bAKIA[0-9A-Z]{16}\b/,
		isKnownProvider: true
	},
	{
		name: "Stripe Live Secret Key",
		provider: "Stripe",
		regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/,
		isKnownProvider: true
	},
	{
		name: "Anthropic API Key",
		provider: "Anthropic",
		regex: /\bsk-ant-(?:api03-)?[a-zA-Z0-9_-]{32,}\b/,
		isKnownProvider: true
	},
	{
		name: "OpenAI API Key",
		provider: "OpenAI",
		regex: /\bsk-(?!ant-)(?:proj-|admin-)?[a-zA-Z0-9_-]{32,}\b/,
		isKnownProvider: true
	},
	{
		name: "GitHub Personal Access Token",
		provider: "GitHub",
		regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,}\b/,
		isKnownProvider: true
	},
	{
		name: "Slack Token",
		provider: "Slack",
		regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,64}\b/,
		isKnownProvider: true
	},
	{
		name: "Slack Incoming Webhook",
		provider: "Slack",
		regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9a-zA-Z]+/,
		isKnownProvider: true
	},
	{
		name: "Discord Webhook URL",
		provider: "Discord",
		regex: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,}/,
		isKnownProvider: true
	},
	{
		name: "Google Cloud API Key",
		provider: "Google Cloud",
		regex: /\bAIza[0-9A-Za-z-_]{35}\b/,
		isKnownProvider: true
	},
	{
		name: "Google Cloud Service Account Key",
		provider: "Google Cloud",
		regex: /"type":\s*"service_account"[\s\S]*?"private_key":\s*"-----BEGIN PRIVATE KEY/,
		isKnownProvider: true
	},
	{
		name: "Azure Storage Account Key / Connection String",
		provider: "Azure",
		regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[0-9a-zA-Z+/=]{64,88}/,
		isKnownProvider: true
	},
	{
		name: "Database Connection URI with Password",
		provider: "Database",
		regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^:\s/]+:([^@\s]{3,})@[^\s"']+/,
		isKnownProvider: true
	},
	{
		name: "JSON Web Token (JWT)",
		provider: "JWT",
		regex: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/,
		isKnownProvider: true
	},
	{
		name: "Private Key (PEM / OpenSSH / EC)",
		provider: "Crypto",
		regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
		isKnownProvider: true
	}
];
/**
* Generic Sensitive Key Names (e.g. in env, headers, or query params)
*/
const SENSITIVE_KEY_NAMES = [
	"API_KEY",
	"APIKEY",
	"SECRET",
	"SECRET_KEY",
	"AUTH_TOKEN",
	"ACCESS_TOKEN",
	"BEARER_TOKEN",
	"PASSWORD",
	"PASSWD",
	"PASS",
	"PRIVATE_KEY",
	"CREDENTIAL",
	"CREDENTIALS",
	"TOKEN",
	"AUTH"
];
function matchesKnownProviderPattern(text) {
	for (const pat of SECRET_PATTERNS) {
		const match = pat.regex.exec(text);
		if (match) {
			if (pat.provider === "Database" && match[1]) {
				if (isPureVariableReferenceOrPlaceholder(match[1])) continue;
				const raw = match[0];
				return {
					patternName: pat.name,
					provider: pat.provider,
					isKnownProvider: pat.isKnownProvider,
					rawMatched: raw,
					masked: maskSecret(raw)
				};
			}
			const raw = match[0];
			return {
				patternName: pat.name,
				provider: pat.provider,
				isKnownProvider: pat.isKnownProvider,
				rawMatched: raw,
				masked: maskSecret(raw)
			};
		}
	}
	return null;
}
/**
* Detect secrets in a string, optionally considering the key/field name context.
* Returns matches with strictly masked representations.
*/
function detectSecrets(text, keyOrContext) {
	if (!text || typeof text !== "string") return [];
	const trimmed = text.trim();
	if (!trimmed) return [];
	const withDefault = extractDefaultFromVarSubstitution(trimmed);
	if (withDefault !== null) {
		const defVal = withDefault.defaultValue.trim();
		if (!defVal) return [];
		return detectSecrets(defVal, keyOrContext || withDefault.varName);
	}
	if (isSafeOrVariableReference(trimmed, keyOrContext)) return [];
	const matches = [];
	for (const pat of SECRET_PATTERNS) {
		const match = pat.regex.exec(trimmed);
		if (match) {
			if (pat.provider === "Database" && match[1]) {
				if (isPureVariableReferenceOrPlaceholder(match[1])) continue;
			}
			const raw = match[0];
			matches.push({
				patternName: pat.name,
				provider: pat.provider,
				isKnownProvider: pat.isKnownProvider,
				rawMatched: raw,
				masked: maskSecret(raw)
			});
		}
	}
	if (matches.length > 0) return matches;
	if (/^(?:https?|wss?):\/\//i.test(trimmed)) try {
		const parsed = new URL(trimmed);
		if (parsed.password && !isPureVariableReferenceOrPlaceholder(parsed.password)) matches.push({
			patternName: "URL Userinfo Password",
			provider: "URL",
			isKnownProvider: false,
			rawMatched: parsed.password,
			masked: maskSecret(parsed.password)
		});
		for (const [qKey, qVal] of parsed.searchParams.entries()) {
			if (!qVal || isPureVariableReferenceOrPlaceholder(qVal, qKey)) continue;
			if (SENSITIVE_KEY_REGEX.test(qKey) && qVal.trim().length >= 6) matches.push({
				patternName: `Secret in URL query parameter (${qKey})`,
				provider: "URL Query",
				isKnownProvider: false,
				rawMatched: qVal,
				masked: maskSecret(qVal)
			});
		}
		if (matches.length > 0) return matches;
	} catch {}
	const bearerMatch = /^(?:Bearer|Basic)\s+(.+)$/i.exec(trimmed);
	if (bearerMatch) {
		const tokenPart = bearerMatch[1].trim();
		if (!isPureVariableReferenceOrPlaceholder(tokenPart, keyOrContext) && tokenPart.length >= 6) {
			matches.push({
				patternName: "Hardcoded Authorization Bearer/Basic Token",
				provider: "HTTP Auth",
				isKnownProvider: false,
				rawMatched: tokenPart,
				masked: maskSecret(tokenPart)
			});
			return matches;
		}
	}
	const ctx = (keyOrContext || "").trim();
	if (ctx && SENSITIVE_KEY_REGEX.test(ctx)) {
		if (/^[0-9a-f]{40}$/i.test(trimmed) || /^[0-9a-f]{64}$/i.test(trimmed)) {
			matches.push({
				patternName: `Hex Secret in ${ctx}`,
				provider: "Generic Secret",
				isKnownProvider: false,
				rawMatched: trimmed,
				masked: maskSecret(trimmed)
			});
			return matches;
		}
		if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
			matches.push({
				patternName: `UUID Credential in ${ctx}`,
				provider: "Generic Secret",
				isKnownProvider: false,
				rawMatched: trimmed,
				masked: maskSecret(trimmed)
			});
			return matches;
		}
		if (trimmed.length >= 8) {
			matches.push({
				patternName: `Literal Secret in ${ctx}`,
				provider: "Generic Secret",
				isKnownProvider: false,
				rawMatched: trimmed,
				masked: maskSecret(trimmed)
			});
			return matches;
		}
	}
	return matches;
}
// ../castov-core/dist/audit/rules/cas001-007.js
/**
* Client-specific remediation messages (Requirement B & Round 3 item 4):
* - Assertive syntax recommendations ONLY where a live verbatim documentation quote proves the syntax.
* - For Claude Code, recommends "${KEY}" only (without ":-default" to avoid encouraging literal default secrets).
* - Does NOT mix Cline with VS Code.
* - Uses neutral guidance wherever upstream docs do not explicitly document variable interpolation syntax.
*/
function getClientSpecificRemediation(clientName, filePath, keyName) {
	const normPath = filePath.replace(/\\/g, "/").toLowerCase();
	const normClient = (clientName || "").toLowerCase();
	if (normClient === "cursor" || normPath.includes("/.cursor/mcp.json") || normPath.endsWith(".cursor/mcp.json")) return `Use "\${env:${keyName}}" in Cursor mcp.json and keep the secret outside the file and outside git (Docs: https://cursor.com/docs/mcp).`;
	if ((normClient === "vs code" || normPath.includes("/.vscode/mcp.json") || normPath.endsWith(".vscode/mcp.json")) && !normClient.includes("cline") && !normPath.includes("cline") && !normPath.includes("saoudrizwan.claude-dev")) return `Use "\${input:${keyName}}" or "\${env:${keyName}}" in .vscode/mcp.json and keep the secret outside the file and outside git (Docs: https://code.visualstudio.com/docs/agents/reference/mcp-configuration).`;
	if (normClient === "claude code" || normPath.endsWith("/.mcp.json") || normPath === ".mcp.json" || normPath.endsWith("/.claude.json") || normPath === ".claude.json") return `Use "\${${keyName}}" in Claude Code config (.mcp.json / ~/.claude.json) and keep the secret outside the file and outside git (Docs: https://code.claude.com/docs/en/mcp).`;
	return `Keep the secret outside the configuration file and outside git version control, and use the client's documented mechanism for passing environment variables.`;
}
function sanitizeArgsForEvidence(args) {
	return args.map((a, idx) => {
		const m = detectSecrets(a, idx > 0 && String(args[idx - 1]).startsWith("-") ? String(args[idx - 1]) : void 0);
		if (m.length > 0) return m[0].masked;
		return a;
	}).join(" ");
}
function runRulesCas001To007(configFile) {
	const findings = [];
	const { filePath, servers } = configFile;
	for (const [serverName, config] of Object.entries(servers)) {
		checkCas001(configFile, serverName, config, findings);
		checkCas002(filePath, serverName, config, findings);
		checkCas003(filePath, serverName, config, findings);
		checkCas004(filePath, serverName, config, findings);
		checkCas005(filePath, serverName, config, findings);
		checkCas006(filePath, serverName, config, findings);
		checkCas007(filePath, serverName, config, findings);
	}
	return findings;
}
/**
* CAS-001: Hardcoded Secret in Server Config (env, args with previous-arg context, headers, url)
*/
function checkCas001(configFile, serverName, config, findings) {
	const filePath = configFile.filePath;
	const clientName = configFile.clientName;
	if (config.env && typeof config.env === "object") for (const [k, v] of Object.entries(config.env)) {
		if (typeof v !== "string" || isSafeOrVariableReference(v, k)) continue;
		const matched = detectSecrets(v, k);
		if (matched.length > 0) {
			const isCritical = matched[0].isKnownProvider;
			findings.push({
				ruleId: "CAS-001",
				severity: isCritical ? "critical" : "high",
				title: isCritical ? `Hardcoded known provider secret in env.${k}` : `Hardcoded secret in env.${k}`,
				whyItMatters: `Exposes credential directly in plain text configuration (${matched[0].patternName}).`,
				suggestedFix: getClientSpecificRemediation(clientName, filePath, k),
				file: filePath,
				serverName,
				keyName: `env.${k}`,
				evidenceMasked: `env.${k}=${matched[0].masked}`
			});
			continue;
		}
		if (SENSITIVE_KEY_NAMES.some((n) => k.toUpperCase().includes(n)) && v.trim().length >= 8) findings.push({
			ruleId: "CAS-001",
			severity: "high",
			title: `Hardcoded literal secret in env.${k}`,
			whyItMatters: `Environment variable "${k}" specifies a sensitive credential name with a static literal value.`,
			suggestedFix: getClientSpecificRemediation(clientName, filePath, k),
			file: filePath,
			serverName,
			keyName: `args_or_env.${k}`,
			evidenceMasked: `env.${k}=${maskSecret(v)}`
		});
	}
	if (Array.isArray(config.args)) for (let i = 0; i < config.args.length; i++) {
		const arg = String(config.args[i]);
		const eqIdx = arg.startsWith("-") ? arg.indexOf("=") : -1;
		if (eqIdx > 0) {
			const flagPart = arg.slice(0, eqIdx);
			const valPart = arg.slice(eqIdx + 1);
			if (!isSafeOrVariableReference(valPart, flagPart)) {
				const matched = detectSecrets(valPart, flagPart);
				if (matched.length > 0) findings.push({
					ruleId: "CAS-001",
					severity: matched[0].isKnownProvider ? "critical" : "high",
					title: `Hardcoded secret in command argument (${flagPart})`,
					whyItMatters: `Exposes ${matched[0].patternName} on CLI argument list, making it visible in system process tables and config files.`,
					suggestedFix: getClientSpecificRemediation(clientName, filePath, "SECRET_ARG"),
					file: filePath,
					serverName,
					keyName: `args[${i}]`,
					evidenceMasked: `args[${i}]=${flagPart}=${matched[0].masked}`
				});
			}
			continue;
		}
		const prevArg = i > 0 ? String(config.args[i - 1]).trim() : "";
		const prevContext = prevArg.startsWith("-") ? prevArg.replace(/^-+/, "") : void 0;
		if (isSafeOrVariableReference(arg, prevContext)) continue;
		const matched = detectSecrets(arg, prevContext);
		if (matched.length > 0) findings.push({
			ruleId: "CAS-001",
			severity: matched[0].isKnownProvider ? "critical" : "high",
			title: prevContext ? `Hardcoded secret in command args after --${prevContext}` : `Hardcoded secret in command args`,
			whyItMatters: `Exposes ${matched[0].patternName} on CLI argument list, making it visible in system process tables and config files.`,
			suggestedFix: getClientSpecificRemediation(clientName, filePath, prevContext ? prevContext.toUpperCase().replace(/[^A-Z0-9_]/g, "_") : "SECRET_ARG"),
			file: filePath,
			serverName,
			keyName: `args[${i}]`,
			evidenceMasked: `args[${i}]=${matched[0].masked}`
		});
	}
	if (config.headers && typeof config.headers === "object") for (const [hk, hv] of Object.entries(config.headers)) {
		if (typeof hv !== "string" || isSafeOrVariableReference(hv, hk)) continue;
		const matched = detectSecrets(hv, hk);
		if (matched.length > 0) findings.push({
			ruleId: "CAS-001",
			severity: matched[0].isKnownProvider ? "critical" : "high",
			title: `Hardcoded credential in headers.${hk}`,
			whyItMatters: `Hardcoded authentication header ${hk} exposes tokens in configuration files.`,
			suggestedFix: getClientSpecificRemediation(clientName, filePath, hk),
			file: filePath,
			serverName,
			keyName: `headers.${hk}`,
			evidenceMasked: `headers.${hk}=${matched[0].masked}`
		});
		else if (hk.toLowerCase().includes("auth") && hv.trim().length >= 8) findings.push({
			ruleId: "CAS-001",
			severity: "high",
			title: `Hardcoded authorization header in headers.${hk}`,
			whyItMatters: `Static token configured in headers is saved in plain text.`,
			suggestedFix: getClientSpecificRemediation(clientName, filePath, hk),
			file: filePath,
			serverName,
			keyName: `headers.${hk}`,
			evidenceMasked: `headers.${hk}=${maskSecret(hv)}`
		});
	}
	if (config.url && typeof config.url === "string") {
		if (!isSafeOrVariableReference(config.url, "url")) {
			const matched = detectSecrets(config.url, "url");
			if (matched.length > 0) {
				let safeOriginPath = "url";
				try {
					const parsedUrl = new URL(config.url);
					safeOriginPath = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;
				} catch {
					safeOriginPath = "url";
				}
				findings.push({
					ruleId: "CAS-001",
					severity: matched[0].isKnownProvider ? "critical" : "high",
					title: `Hardcoded secret in server URL (${matched[0].patternName})`,
					whyItMatters: `Sensitive credentials embedded in URLs are logged in access logs and plaintext configuration files.`,
					suggestedFix: getClientSpecificRemediation(clientName, filePath, "URL_TOKEN"),
					file: filePath,
					serverName,
					keyName: "url",
					evidenceMasked: `url=${safeOriginPath}?${matched[0].masked}`
				});
			}
		}
	}
}
/**
* CAS-002: Unpinned Runtime Launcher
*/
function checkCas002(filePath, serverName, config, findings) {
	const cmd = config.command?.toLowerCase() || "";
	const args = (config.args || []).map((a) => String(a));
	if ((/* @__PURE__ */ new Set([
		"npx",
		"pnpm",
		"bunx",
		"uvx",
		"pipx",
		"dlx"
	])).has(cmd)) {
		let pkgArg = "";
		for (const a of args) {
			if (a === "-y" || a === "--yes" || a === "run" || a === "dlx" || a.startsWith("-")) continue;
			pkgArg = a;
			break;
		}
		if (pkgArg) {
			const hasVersion = /@\d+\.\d+/.test(pkgArg);
			const isLatest = pkgArg.endsWith("@latest");
			if (!hasVersion || isLatest) findings.push({
				ruleId: "CAS-002",
				severity: "medium",
				title: `Unpinned package runner: ${cmd} ${pkgArg}`,
				whyItMatters: `Executing packages without explicit version pinning (${pkgArg}) allows automatic pulling of untested or potentially compromised upstream releases.`,
				suggestedFix: `Pin exact version: e.g. "${pkgArg.split("@")[0]}@1.2.3"`,
				file: filePath,
				serverName,
				keyName: "command",
				evidenceMasked: `${cmd} ${sanitizeArgsForEvidence(args)}`
			});
		}
	}
	if (cmd === "docker") {
		const runIdx = args.indexOf("run");
		if (runIdx !== -1) for (let i = runIdx + 1; i < args.length; i++) {
			const arg = args[i];
			if (arg.startsWith("-")) {
				if ([
					"-v",
					"--volume",
					"-p",
					"-e",
					"--env",
					"--name",
					"--network"
				].includes(arg)) i++;
				continue;
			}
			const isLatest = arg.endsWith(":latest");
			if (!(arg.includes(":") || arg.includes("@sha256:")) || isLatest) findings.push({
				ruleId: "CAS-002",
				severity: "medium",
				title: `Unpinned Docker image: ${arg}`,
				whyItMatters: `Docker containers without explicit immutable tags or SHA256 digests can pull untrusted updates dynamically.`,
				suggestedFix: `Specify immutable container image tag: "${arg.split(":")[0]}:v1.0.0" or @sha256 digest.`,
				file: filePath,
				serverName,
				keyName: "command",
				evidenceMasked: `docker run ... ${arg}`
			});
			break;
		}
	}
}
/**
* CAS-003: Shell Wrapper or Embedded Script
*/
function checkCas003(filePath, serverName, config, findings) {
	const cmd = (config.command || "").toLowerCase();
	const args = (config.args || []).map((a) => String(a));
	const fullCmdLine = [cmd, ...args].join(" ");
	const safeEvidence = [cmd, sanitizeArgsForEvidence(args)].join(" ").slice(0, 80);
	if ((/* @__PURE__ */ new Set([
		"sh",
		"bash",
		"zsh",
		"cmd",
		"cmd.exe",
		"powershell",
		"powershell.exe",
		"pwsh"
	])).has(cmd)) {
		if (args.some((a) => a === "-c" || a.toLowerCase() === "-command" || a.toLowerCase() === "/c")) {
			findings.push({
				ruleId: "CAS-003",
				severity: "high",
				title: `Shell wrapper with embedded command execution (${cmd})`,
				whyItMatters: `Running tools through a shell command string introduces arbitrary command injection and shell escape vulnerabilities.`,
				suggestedFix: `Invoke target binaries directly as "command" without shell wrappers (-c / -Command / /c).`,
				file: filePath,
				serverName,
				keyName: "command",
				evidenceMasked: safeEvidence
			});
			return;
		}
	}
	const hasPipeToShell = /(?:curl|wget)\b[^\n|]+\|\s*(?:sh|bash|zsh|pwsh|powershell)/i.test(fullCmdLine);
	const hasSubshell = /\$\([^)]+\)/.test(fullCmdLine) || /`[^`]+`/.test(fullCmdLine);
	const hasEval = /\beval\b/.test(fullCmdLine);
	if (hasPipeToShell || hasSubshell || hasEval) findings.push({
		ruleId: "CAS-003",
		severity: "high",
		title: `Dangerous script piping or subshell execution in arguments`,
		whyItMatters: `Piping remote downloads to shells or invoking subshells executes unverified code dynamically.`,
		suggestedFix: `Pre-install verified binaries locally and call them directly.`,
		file: filePath,
		serverName,
		keyName: "args",
		evidenceMasked: safeEvidence
	});
}
/**
* CAS-004: Remote Server Security & Data Flow
*/
function checkCas004(filePath, serverName, config, findings) {
	const url = config.url;
	if (!url || typeof url !== "string") return;
	let parsed;
	try {
		parsed = new URL(url);
	} catch {
		return;
	}
	const isLocalhost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1" || parsed.hostname === "[::1]" || parsed.hostname.endsWith(".localhost");
	if (parsed.protocol === "http:" && !isLocalhost) {
		findings.push({
			ruleId: "CAS-004",
			severity: "high",
			title: `Unencrypted remote HTTP MCP server (${parsed.hostname})`,
			whyItMatters: `Remote MCP server communicates over plaintext HTTP, exposing all prompts, code context, and tool responses to interception.`,
			suggestedFix: `Upgrade endpoint to TLS/HTTPS: "https://${parsed.host}${parsed.pathname}"`,
			file: filePath,
			serverName,
			keyName: "url",
			evidenceMasked: `url=${parsed.protocol}//${parsed.host}${parsed.pathname}`
		});
		return;
	}
	if (parsed.protocol === "https:" && !isLocalhost) {
		const headers = config.headers || {};
		if (!Object.keys(headers).some((h) => [
			"authorization",
			"x-api-key",
			"apikey",
			"bearer"
		].includes(h.toLowerCase()))) findings.push({
			ruleId: "CAS-004",
			severity: "medium",
			title: `Remote HTTPS server without visible authorization header`,
			whyItMatters: `Remote endpoint ${parsed.hostname} does not declare authentication headers.`,
			suggestedFix: `Configure an explicit Authorization header using your client's documented variable reference mechanism.`,
			file: filePath,
			serverName,
			keyName: "headers",
			evidenceMasked: `url=${parsed.origin}${parsed.pathname}`
		});
		findings.push({
			ruleId: "CAS-004",
			severity: "info",
			title: `Data flow to third-party remote server (${parsed.hostname})`,
			whyItMatters: `All tool calls dispatched to this server send developer prompts and workspace data to external infrastructure.`,
			suggestedFix: `Verify third-party data processing agreement and privacy policy.`,
			file: filePath,
			serverName,
			keyName: "url.remote",
			evidenceMasked: `remote_host=${parsed.hostname}`
		});
	}
}
/**
* CAS-005: Broad Filesystem Scope
*/
function checkCas005(filePath, serverName, config, findings) {
	const args = (config.args || []).map((a) => String(a));
	for (const arg of args) {
		const trimmed = arg.trim();
		const isRoot = trimmed === "/" || trimmed === "C:\\" || trimmed === "C:/" || trimmed === "c:\\" || trimmed === "c:/";
		const isHome = trimmed === "~" || trimmed === "$HOME" || trimmed === "%USERPROFILE%" || trimmed === "%HOMEPATH%";
		const isBroadUnix = trimmed.startsWith("/home") || trimmed.startsWith("/Users");
		const isBroadWin = /^[a-zA-Z]:\\Users(?:\\[^\\]+)?$/i.test(trimmed);
		if (isRoot || isHome || isBroadUnix || isBroadWin) {
			findings.push({
				ruleId: "CAS-005",
				severity: "high",
				title: `Broad filesystem scope argument: "${trimmed}"`,
				whyItMatters: `Granting access to the filesystem root or home directory ("${trimmed}") allows reading private user documents, SSH keys, and system files.`,
				suggestedFix: `Restrict tool directory scope to the current workspace project: "./"`,
				file: filePath,
				serverName,
				keyName: "args.scope",
				evidenceMasked: `arg=${trimmed}`
			});
			break;
		}
	}
}
/**
* CAS-006: Docker Container Risks (--privileged, docker.sock, root volume mount -v /:/, --network host)
*/
function checkCas006(filePath, serverName, config, findings) {
	if ((config.command || "").toLowerCase() !== "docker") return;
	const args = (config.args || []).map((a) => String(a));
	const fullArgs = args.join(" ");
	if (args.includes("--privileged")) findings.push({
		ruleId: "CAS-006",
		severity: "critical",
		title: `Docker container running in privileged mode (--privileged)`,
		whyItMatters: `Privileged containers disable security isolation, granting full root access to host devices and kernel capabilities.`,
		suggestedFix: `Remove --privileged and grant only strictly required capabilities (--cap-add).`,
		file: filePath,
		serverName,
		keyName: "args.privileged",
		evidenceMasked: `docker ... --privileged`
	});
	if (fullArgs.includes("/var/run/docker.sock") || fullArgs.includes("docker.sock")) findings.push({
		ruleId: "CAS-006",
		severity: "critical",
		title: `Host docker.sock mounted into container`,
		whyItMatters: `Mounting the Docker daemon socket provides root-equivalent privilege escalation over the entire host machine.`,
		suggestedFix: `Remove docker.sock volume mount to maintain host container boundary isolation.`,
		file: filePath,
		serverName,
		keyName: "args.docker_sock",
		evidenceMasked: `volume mount: /var/run/docker.sock`
	});
	if (fullArgs.includes("-v /:/") || fullArgs.includes("--volume /:/") || args.some((a) => /^\/:\/[^:\s]+/.test(a))) findings.push({
		ruleId: "CAS-006",
		severity: "high",
		title: `Host filesystem root mounted into Docker container (-v /:/)`,
		whyItMatters: `Mounting host root enables reading and writing all host operating system files directly from the container.`,
		suggestedFix: `Mount only project directory: "-v ./:/app"`,
		file: filePath,
		serverName,
		keyName: "args.root_mount",
		evidenceMasked: `-v /:/`
	});
	if (args.includes("--network=host") || fullArgs.includes("--network host")) findings.push({
		ruleId: "CAS-006",
		severity: "high",
		title: `Docker host network stack attached (--network host)`,
		whyItMatters: `Host networking bypasses container network isolation, allowing tools to access local loopback services.`,
		suggestedFix: `Use bridge network isolation with explicit port bindings.`,
		file: filePath,
		serverName,
		keyName: "args.network_host",
		evidenceMasked: `--network host`
	});
}
/**
* CAS-007: Auto-Approve / Always-Allow Permissions
*/
function checkCas007(filePath, serverName, config, findings) {
	const autoApprove = config.autoApprove ?? config.alwaysAllow;
	if (!autoApprove) return;
	const SENSITIVE_ACTIONS = [
		"write",
		"edit",
		"execute",
		"exec",
		"terminal",
		"bash",
		"shell",
		"delete",
		"remove",
		"rm"
	];
	if (autoApprove === true || Array.isArray(autoApprove) && autoApprove.includes("*")) {
		findings.push({
			ruleId: "CAS-007",
			severity: "high",
			title: `Wildcard auto-approval enabled (autoApprove: *)`,
			whyItMatters: `All tool actions from "${serverName}" execute automatically without human verification or confirmation prompt.`,
			suggestedFix: `Remove wildcard and require human-in-the-loop confirmation for dangerous operations.`,
			file: filePath,
			serverName,
			keyName: "autoApprove",
			evidenceMasked: `autoApprove: *`
		});
		return;
	}
	if (Array.isArray(autoApprove) && autoApprove.length > 0) {
		const dangerousTools = autoApprove.filter((tool) => SENSITIVE_ACTIONS.some((act) => String(tool).toLowerCase().includes(act)));
		if (dangerousTools.length > 0) findings.push({
			ruleId: "CAS-007",
			severity: "high",
			title: `Auto-approval configured for write/execute tools: [${dangerousTools.join(", ")}]`,
			whyItMatters: `Automatically approving write or shell execution actions allows autonomous agents to modify files or execute arbitrary commands without review.`,
			suggestedFix: `Enforce interactive confirmation for destructive tools: [${dangerousTools.join(", ")}]`,
			file: filePath,
			serverName,
			keyName: "autoApprove",
			evidenceMasked: `autoApprove: [${dangerousTools.join(", ")}]`
		});
		else findings.push({
			ruleId: "CAS-007",
			severity: "medium",
			title: `Auto-approval configured for ${autoApprove.length} tool(s)`,
			whyItMatters: `Pre-approving tools bypasses user confirmation prompts for actions performed by this MCP server.`,
			suggestedFix: `Audit approved tools to ensure read-only safety.`,
			file: filePath,
			serverName,
			keyName: "autoApprove",
			evidenceMasked: `autoApprove: [${autoApprove.slice(0, 3).join(", ")}${autoApprove.length > 3 ? "..." : ""}]`
		});
	}
}
// ../castov-core/dist/audit/pure-path.js
/**
* Pure platform-agnostic path utilities (No Node.js `node:path` dependency).
* Supports both Windows (C:\..., backslashes, drive letters) and POSIX (/..., relative).
* Always standardizes internal directory separators to forward slashes ('/').
*/
function normalizePath(pathStr) {
	if (!pathStr) return "";
	let p = pathStr.replace(/\\/g, "/");
	const driveMatch = /^[a-zA-Z]:/.exec(p);
	const drive = driveMatch ? driveMatch[0] : "";
	if (drive) p = p.slice(drive.length);
	const isAbsolute = p.startsWith("/");
	const segments = p.split("/").filter((s) => s.length > 0 && s !== ".");
	const stack = [];
	for (const seg of segments) if (seg === "..") {
		if (stack.length > 0 && stack[stack.length - 1] !== "..") stack.pop();
		else if (!isAbsolute) stack.push("..");
	} else stack.push(seg);
	let result = stack.join("/");
	if (isAbsolute) result = "/" + result;
	if (drive) {
		result = drive + (result.startsWith("/") ? result : "/" + result);
		if (result.endsWith(":")) result += "/";
	}
	return result || (isAbsolute ? "/" : ".");
}
function pureBasename(pathStr) {
	if (!pathStr) return "";
	const normalized = pathStr.replace(/\\/g, "/").replace(/\/+$/, "");
	const idx = normalized.lastIndexOf("/");
	if (idx === -1) {
		if (/^[a-zA-Z]:$/.test(normalized)) return "";
		return normalized;
	}
	return normalized.slice(idx + 1);
}
function pureDirname(pathStr) {
	if (!pathStr) return ".";
	let p = pathStr.replace(/\\/g, "/").replace(/\/+$/, "");
	if (!p) return "/";
	const driveMatch = /^[a-zA-Z]:/.exec(p);
	const drive = driveMatch ? driveMatch[0] : "";
	if (drive) {
		p = p.slice(drive.length);
		if (!p || p === "/") return drive + "/";
	}
	const idx = p.lastIndexOf("/");
	if (idx === -1) return drive ? drive + "/" : ".";
	if (idx === 0) return drive ? drive + "/" : "/";
	const dirPart = p.slice(0, idx);
	return drive ? drive + dirPart : dirPart;
}
/**
* Resolves a sequence of paths or path segments into an absolute path.
* Requires the base (or at least one root component in the sequence) to be an absolute path
* (e.g. starting with `/` on POSIX or `C:/` on Windows).
*/
function pureResolve(...paths) {
	let resolvedDrive = "";
	let resolvedPath = "";
	let isAbs = false;
	for (let i = paths.length - 1; i >= 0; i--) {
		const raw = paths[i];
		if (!raw || typeof raw !== "string") continue;
		const p = raw.replace(/\\/g, "/");
		const driveMatch = /^[a-zA-Z]:/.exec(p);
		const drive = driveMatch ? driveMatch[0] : "";
		const withoutDrive = drive ? p.slice(drive.length) : p;
		if (withoutDrive.startsWith("/")) {
			isAbs = true;
			resolvedPath = withoutDrive + (resolvedPath ? "/" + resolvedPath : "");
			if (drive) resolvedDrive = drive;
			break;
		}
		if (drive && !withoutDrive.startsWith("/")) {
			resolvedDrive = drive;
			resolvedPath = "/" + withoutDrive + (resolvedPath ? "/" + resolvedPath : "");
			isAbs = true;
			break;
		}
		resolvedPath = withoutDrive + (resolvedPath ? "/" + resolvedPath : "");
	}
	return normalizePath((resolvedDrive ? resolvedDrive : "") + (isAbs && !resolvedPath.startsWith("/") ? "/" : "") + resolvedPath || ".");
}
function pureRelative(from, to) {
	const normFrom = normalizePath(from);
	const normTo = normalizePath(to);
	const fromDriveMatch = /^[a-zA-Z]:/i.exec(normFrom);
	const toDriveMatch = /^[a-zA-Z]:/i.exec(normTo);
	const fromDrive = fromDriveMatch ? fromDriveMatch[0].toUpperCase() : "";
	const toDrive = toDriveMatch ? toDriveMatch[0].toUpperCase() : "";
	if (fromDrive !== toDrive) return normTo;
	const cleanFrom = (fromDrive ? normFrom.slice(2) : normFrom).replace(/^\/+/, "");
	const cleanTo = (toDrive ? normTo.slice(2) : normTo).replace(/^\/+/, "");
	const fromSegs = cleanFrom ? cleanFrom.split("/") : [];
	const toSegs = cleanTo ? cleanTo.split("/") : [];
	let common = 0;
	while (common < fromSegs.length && common < toSegs.length && fromSegs[common] === toSegs[common]) common++;
	const upCount = fromSegs.length - common;
	const relSegs = [];
	for (let i = 0; i < upCount; i++) relSegs.push("..");
	for (let i = common; i < toSegs.length; i++) relSegs.push(toSegs[i]);
	return relSegs.join("/") || ".";
}
// ../castov-core/dist/audit/sha256.js
function utf8Encode(str) {
	const binary = [];
	for (let i = 0; i < str.length; i++) {
		let code = str.charCodeAt(i);
		if (code < 128) binary.push(code);
		else if (code < 2048) {
			binary.push(192 | code >> 6);
			binary.push(128 | code & 63);
		} else if (code >= 55296 && code <= 56319) {
			i++;
			const next = str.charCodeAt(i);
			const codePoint = 65536 + ((code & 1023) << 10 | next & 1023);
			binary.push(240 | codePoint >> 18);
			binary.push(128 | codePoint >> 12 & 63);
			binary.push(128 | codePoint >> 6 & 63);
			binary.push(128 | codePoint & 63);
		} else {
			binary.push(224 | code >> 12);
			binary.push(128 | code >> 6 & 63);
			binary.push(128 | code & 63);
		}
	}
	return new Uint8Array(binary);
}
function rotr(x, n) {
	return x >>> n | x << 32 - n;
}
const K = [
	1116352408,
	1899447441,
	3049323471,
	3921009573,
	961987163,
	1508970993,
	2453635748,
	2870763221,
	3624381080,
	310598401,
	607225278,
	1426881987,
	1925078388,
	2162078206,
	2614888103,
	3248222580,
	3835390401,
	4022224774,
	264347078,
	604807628,
	770255983,
	1249150122,
	1555081692,
	1996064986,
	2554220882,
	2821834349,
	2952996808,
	3210313671,
	3336571891,
	3584528711,
	113926993,
	338241895,
	666307205,
	773529912,
	1294757372,
	1396182291,
	1695183700,
	1986661051,
	2177026350,
	2456956037,
	2730485921,
	2820302411,
	3259730800,
	3345764771,
	3516065817,
	3600352804,
	4094571909,
	275423344,
	430227734,
	506948616,
	659060556,
	883997877,
	958139571,
	1322822218,
	1537002063,
	1747873779,
	1955562222,
	2024104815,
	2227730452,
	2361852424,
	2428436474,
	2756734187,
	3204031479,
	3329325298
];
function sha256(input) {
	const bytes = utf8Encode(input);
	const bitLen = bytes.length * 8;
	const withPadding = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64);
	withPadding.set(bytes);
	withPadding[bytes.length] = 128;
	const view = new DataView(withPadding.buffer);
	view.setUint32(withPadding.length - 4, bitLen >>> 0, false);
	view.setUint32(withPadding.length - 8, Math.floor(bitLen / 4294967296), false);
	let h0 = 1779033703;
	let h1 = 3144134277;
	let h2 = 1013904242;
	let h3 = 2773480762;
	let h4 = 1359893119;
	let h5 = 2600822924;
	let h6 = 528734635;
	let h7 = 1541459225;
	const w = /* @__PURE__ */ new Uint32Array(64);
	for (let offset = 0; offset < withPadding.length; offset += 64) {
		for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4, false);
		for (let i = 16; i < 64; i++) {
			const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3;
			const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
			w[i] = w[i - 16] + s0 + w[i - 7] + s1 | 0;
		}
		let a = h0;
		let b = h1;
		let c = h2;
		let d = h3;
		let e = h4;
		let f = h5;
		let g = h6;
		let h = h7;
		for (let i = 0; i < 64; i++) {
			const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = e & f ^ ~e & g;
			const temp1 = h + s1 + ch + K[i] + w[i] | 0;
			const temp2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + (a & b ^ a & c ^ b & c) | 0;
			h = g;
			g = f;
			f = e;
			e = d + temp1 | 0;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2 | 0;
		}
		h0 = h0 + a | 0;
		h1 = h1 + b | 0;
		h2 = h2 + c | 0;
		h3 = h3 + d | 0;
		h4 = h4 + e | 0;
		h5 = h5 + f | 0;
		h6 = h6 + g | 0;
		h7 = h7 + h | 0;
	}
	return [
		h0,
		h1,
		h2,
		h3,
		h4,
		h5,
		h6,
		h7
	].map((val) => (val >>> 0).toString(16).padStart(8, "0")).join("");
}
// ../castov-core/dist/audit/rules/cas008-015.js
function checkIsEnvIgnored(fileName, ignoreText) {
	if (!ignoreText) return false;
	const lines = ignoreText.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
	for (const pattern of lines) {
		if (pattern === ".env" || pattern === ".env*" || pattern === "**/.env*" || pattern === "**/.env" || pattern === "**/.env.*" || pattern === "*.env" || pattern === ".env.*") return true;
		if (pattern === fileName || pattern === `/${fileName}` || pattern === `**/${fileName}` || pattern === `./${fileName}`) return true;
	}
	return false;
}
/**
* Check if Claude Code `permissions.deny` rules in `.claude/settings.json` / `.claude/settings.local.json` / `~/.claude/settings.json`
* block reading the given `.env` file.
* Verbatim Quote: '"permissions" : { "allow" : [ "Bash(npm run lint)" , "Bash(npm run test *)" ], "deny" : [ "Read(./.env)" , "Read(./.env.*)" ] }'
* Source: https://code.claude.com/docs/en/settings (Fetched: 2026-10-26)
*/
function checkIsEnvDeniedInClaudeSettings(fileName, claudeSettings = []) {
	for (const s of claudeSettings) for (const rawRule of s.denyRules) {
		const m = /^Read\((.+)\)$/i.exec(rawRule.trim());
		if (!m) continue;
		const pat = m[1].trim().replace(/^\.\//, "");
		if (pat === ".env" || pat === ".env*" || pat === "**/.env" || pat === "**/.env*" || pat === fileName || pat === `**/${fileName}`) {
			if (pat === ".env" && fileName !== ".env") continue;
			return true;
		}
		if ((pat === ".env.*" || pat === "**/.env.*") && fileName.startsWith(".env.")) return true;
	}
	return false;
}
/**
* CAS-008: .env AI Agent Context Exposure & Unrespected .claudeignore
* - Claude Code does NOT respect `.claudeignore` (documented in official issues and absent from https://code.claude.com/docs/en/settings).
*   Instead, Claude Code requires `permissions.deny` (e.g. `Read(./.env)`, `Read(./.env.*)`) in `.claude/settings.json`.
*   If `.claudeignore` is present, emits a finding ("ملف تجاهل غير محترم من Claude Code (.claudeignore)").
* - For Cursor, `.cursorignore` is verified via https://cursor.com/docs/context/ignore-files.
* - Unverified ignore files (.aiignore, .windsurfignore, .copilotignore) are NOT relied upon.
* - Remediation explicitly recommends keeping secrets outside the project directory (e.g., OS keychain or external secret manager).
*/
function checkCas008(envFiles, hasCursorIgnore, cursorIgnoreContent, options = {}) {
	const findings = [];
	const { hasClaudeIgnore = false, claudeIgnorePath, claudeSettings = [] } = options;
	if (hasClaudeIgnore && claudeIgnorePath) findings.push({
		ruleId: "CAS-008",
		severity: "medium",
		title: `ملف تجاهل غير محترم من Claude Code (.claudeignore)`,
		whyItMatters: `Claude Code does not honor ".claudeignore" for blocking file reads. Relying on ".claudeignore" leaves ".env" and secret files accessible to the agent.`,
		suggestedFix: `Configure "permissions.deny": ["Read(./.env)", "Read(./.env.*)"] in ".claude/settings.json" (or "~/.claude/settings.json") as documented at https://code.claude.com/docs/en/settings, and store sensitive secrets outside the project directory.`,
		file: claudeIgnorePath,
		keyName: ".claudeignore:unrespected",
		evidenceMasked: `unrespected_ignore_file: .claudeignore`
	});
	for (const env of envFiles) {
		if (env.fileName === ".env.example" || env.fileName === ".env.template" || env.fileName === ".env.sample") continue;
		const isProtectedByCursorIgnore = hasCursorIgnore && checkIsEnvIgnored(env.fileName, cursorIgnoreContent);
		const isProtectedByClaudeDeny = checkIsEnvDeniedInClaudeSettings(env.fileName, claudeSettings);
		if (!((isProtectedByCursorIgnore || isProtectedByClaudeDeny) && !(hasClaudeIgnore && !isProtectedByClaudeDeny))) findings.push({
			ruleId: "CAS-008",
			severity: "medium",
			title: `Environment file "${env.fileName}" is not protected from AI agent context ingestion`,
			whyItMatters: `Plaintext "${env.fileName}" exists in the workspace without a verified agent access block (Cursor ".cursorignore" or Claude Code "permissions.deny" in ".claude/settings.json"). Note that ".claudeignore" is not respected by Claude Code.`,
			suggestedFix: `For Claude Code, add "permissions": { "deny": ["Read(./.env)", "Read(./.env.*)"] } in ".claude/settings.json" (https://code.claude.com/docs/en/settings). For Cursor, add "${env.fileName}" to ".cursorignore" (https://cursor.com/docs/context/ignore-files). Best practice: keep real secrets outside the project directory entirely.`,
			file: env.filePath,
			keyName: env.fileName,
			evidenceMasked: `agent_context_unprotected: ${env.fileName}`
		});
	}
	return findings;
}
/**
* CAS-009: Literal secret in config/env file OR .env tracked/unignored in git
* Severity: High
*/
function checkCas009(envFiles, hasGitignore, gitignoreContent) {
	const findings = [];
	for (const env of envFiles) {
		if (!(env.fileName === ".env.example" || env.fileName === ".env.template" || env.fileName === ".env.sample")) {
			if (env.isGitTracked) findings.push({
				ruleId: "CAS-009",
				severity: "high",
				title: `Environment file "${env.fileName}" is tracked in Git`,
				whyItMatters: `Tracking "${env.fileName}" in version control exposes secrets to repository history and clones.`,
				suggestedFix: `Run "git rm --cached ${env.fileName}", add "${env.fileName}" to .gitignore, and rotate any exposed secrets.`,
				file: env.filePath,
				keyName: `${env.fileName}:git_tracked`,
				evidenceMasked: `tracked_in_git: ${env.fileName}`
			});
			else if (!hasGitignore || !checkIsEnvIgnored(env.fileName, gitignoreContent)) findings.push({
				ruleId: "CAS-009",
				severity: "high",
				title: `Environment file "${env.fileName}" is not ignored in .gitignore`,
				whyItMatters: `Unignored "${env.fileName}" risks accidental commits during git staging.`,
				suggestedFix: `Add ".env*" to your root .gitignore file.`,
				file: env.filePath,
				keyName: `${env.fileName}:git_unignored`,
				evidenceMasked: `gitignore_missing: ${env.fileName}`
			});
		}
		if (env.rawContent) {
			const lines = env.rawContent.split(/\r?\n/);
			for (let i = 0; i < lines.length; i++) {
				const line = lines[i].trim();
				if (!line || line.startsWith("#") || !line.includes("=")) continue;
				const eqIdx = line.indexOf("=");
				const k = line.slice(0, eqIdx).trim();
				const rawVal = line.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "");
				if (!rawVal || isSafeOrVariableReference(rawVal, k)) continue;
				const secrets = detectSecrets(rawVal, k);
				if (secrets.length > 0) findings.push({
					ruleId: "CAS-009",
					severity: "high",
					title: `Hardcoded secret in ${env.fileName} (${k})`,
					whyItMatters: `File "${env.fileName}" contains a literal credential (${secrets[0].patternName}).`,
					suggestedFix: `Keep literal secrets out of tracked or unignored files, store secrets outside the project directory, and replace with placeholders in templates.`,
					file: env.filePath,
					line: i + 1,
					keyName: k,
					evidenceMasked: `${k}=${secrets[0].masked}`
				});
			}
		}
	}
	return findings;
}
/**
* CAS-010: Duplicate or conflicting MCP server definitions across project and user scopes
* Severity: Low
*/
function checkCas010(configFiles) {
	const findings = [];
	const serverOccurrences = /* @__PURE__ */ new Map();
	for (const cfg of configFiles) {
		if (cfg.isEnvFile) continue;
		for (const sName of Object.keys(cfg.servers)) {
			const list = serverOccurrences.get(sName) || [];
			list.push({
				file: cfg.filePath,
				scope: cfg.scope
			});
			serverOccurrences.set(sName, list);
		}
	}
	for (const [sName, list] of serverOccurrences.entries()) if (list.length > 1) {
		const filesStr = list.map((l) => `${l.file} (${l.scope})`).join(", ");
		findings.push({
			ruleId: "CAS-010",
			severity: "low",
			title: `Conflicting duplicate MCP server name: "${sName}"`,
			whyItMatters: `Server "${sName}" is defined in multiple configuration files (${filesStr}), which can cause ambiguous overrides between project and user scopes.`,
			suggestedFix: `Use unique, descriptive MCP server names across project and user configurations.`,
			file: list[0].file,
			serverName: sName,
			keyName: sName,
			evidenceMasked: `defined in ${list.length} files`
		});
	}
	return findings;
}
/**
* Normalize a URL by stripping userinfo and query parameter values (keeping sorted query key names only).
*/
function normalizeUrlWithoutSecrets(rawUrl) {
	if (!rawUrl || typeof rawUrl !== "string") return "";
	const trimmed = rawUrl.trim();
	if (!trimmed) return "";
	try {
		const parsed = new URL(trimmed);
		const queryKeys = Array.from(new Set(Array.from(parsed.searchParams.keys()))).sort();
		const querySkeleton = queryKeys.length > 0 ? `?${queryKeys.join("&")}` : "";
		return `${parsed.protocol}//${parsed.host}${parsed.pathname}${querySkeleton}`;
	} catch {
		const base = trimmed.split("?")[0];
		if (detectSecrets(base).length > 0) return "<SECRET_URL>";
		return base;
	}
}
/**
* Normalize an MCP server definition for CAS-011 baseline drift detection (Requirement E):
* client + scope + serverName + command + args (secrets replaced with "<SECRET>") +
* sorted env keys without values + URL without query values + transport.
*/
function computeNormalizedServerEntry(cfg, serverName, server, targetDir, ctx) {
	const client = (cfg.clientName || "generic").toLowerCase();
	const scope = cfg.scope;
	const command = (server.command || "").trim();
	const rawArgs = (server.args || []).map((a) => String(a));
	const normalizedArgs = rawArgs.map((s, idx) => {
		const prevArg = idx > 0 ? rawArgs[idx - 1].trim() : "";
		const prevContext = prevArg.startsWith("-") ? prevArg.replace(/^-+/, "") : void 0;
		if (!isSafeOrVariableReference(s, prevContext) && detectSecrets(s, prevContext).length > 0) return "<SECRET>";
		return s;
	});
	const envKeys = Object.keys(server.env || {}).sort();
	const normalizedUrl = normalizeUrlWithoutSecrets(server.url);
	const transport = String(server.transport || server.type || (server.url ? "http" : "stdio")).toLowerCase();
	const canonicalDefinition = JSON.stringify({
		client,
		scope,
		serverName,
		command,
		args: normalizedArgs,
		envKeys,
		url: normalizedUrl,
		transport
	});
	const coreExecution = JSON.stringify({
		command,
		args: normalizedArgs,
		url: normalizedUrl,
		transport
	});
	const hashFn = ctx?.sha256 || sha256;
	const definitionHash = hashFn(canonicalDefinition);
	const coreExecutionHash = hashFn(coreExecution);
	return {
		client,
		scope,
		serverName,
		file: pureRelative(targetDir, cfg.filePath).replace(/\\/g, "/") || cfg.filePath.replace(/\\/g, "/"),
		definitionHash,
		coreExecutionHash
	};
}
/**
* Build map of all normalized servers across discovered config files
*/
function buildBaselineServersMap(configFiles, targetDir, ctx) {
	const map = {};
	for (const cfg of configFiles) {
		if (cfg.isEnvFile) continue;
		for (const [sName, sConfig] of Object.entries(cfg.servers)) {
			const entry = computeNormalizedServerEntry(cfg, sName, sConfig, targetDir, ctx);
			const key = `${entry.client}|${entry.scope}|${sName}`;
			map[key] = entry;
		}
	}
	return map;
}
/**
* CAS-011: Baseline Drift / Rug Pull Detection (Requirement E)
* - Modified command, args, or url (or definition) -> High
* - New server added -> Medium
* - Server removed -> Info
*/
function checkCas011(currentServers, baselineServers, targetDir) {
	const findings = [];
	if (!baselineServers) return findings;
	for (const [key, curr] of Object.entries(currentServers)) {
		const prev = baselineServers[key];
		const absFile = pureResolve(targetDir, curr.file);
		if (!prev) {
			findings.push({
				ruleId: "CAS-011",
				severity: "medium",
				title: `New MCP server added since baseline: "${curr.serverName}"`,
				whyItMatters: `Server "${curr.serverName}" was not present in the saved baseline and introduces new tool execution capabilities.`,
				suggestedFix: `Audit the new server configuration and update the baseline if approved.`,
				file: absFile,
				serverName: curr.serverName,
				keyName: `drift.added.${curr.serverName}`,
				evidenceMasked: `new_server=${curr.serverName} (hash=${curr.definitionHash.slice(0, 12)})`
			});
			continue;
		}
		if (curr.definitionHash !== prev.definitionHash) findings.push({
			ruleId: "CAS-011",
			severity: "high",
			title: `MCP server definition drifted from baseline: "${curr.serverName}"`,
			whyItMatters: `The command, arguments, URL, transport, or environment keys of "${curr.serverName}" changed since the baseline was recorded (potential supply-chain or rug-pull modification).`,
			suggestedFix: `Inspect changes to "${curr.serverName}" against version control and re-verify package/URL integrity.`,
			file: absFile,
			serverName: curr.serverName,
			keyName: `drift.modified.${curr.serverName}`,
			evidenceMasked: `baseline_hash=${prev.definitionHash.slice(0, 12)} != current_hash=${curr.definitionHash.slice(0, 12)}`
		});
	}
	for (const [key, prev] of Object.entries(baselineServers)) if (!currentServers[key]) {
		const absFile = pureResolve(targetDir, prev.file);
		findings.push({
			ruleId: "CAS-011",
			severity: "info",
			title: `MCP server removed since baseline: "${prev.serverName}"`,
			whyItMatters: `Server "${prev.serverName}" was recorded in the baseline but is no longer present in the configuration.`,
			suggestedFix: `Update the baseline file if the removal of "${prev.serverName}" was intentional.`,
			file: absFile,
			serverName: prev.serverName,
			keyName: `drift.removed.${prev.serverName}`,
			evidenceMasked: `removed_server=${prev.serverName}`
		});
	}
	return findings;
}
/**
* CAS-013: Deprecated or Insecure Transport Protocols
*/
function checkCas013(configFiles) {
	const findings = [];
	for (const cfg of configFiles) {
		if (cfg.isEnvFile) continue;
		for (const [serverName, server] of Object.entries(cfg.servers)) {
			if (server.url && typeof server.url === "string") {
				if (server.url.startsWith("ws://") && !server.url.includes("localhost") && !server.url.includes("127.0.0.1")) {
					const safeUrl = normalizeUrlWithoutSecrets(server.url);
					findings.push({
						ruleId: "CAS-013",
						severity: "high",
						title: `Insecure WebSocket transport: ${safeUrl}`,
						whyItMatters: "Unencrypted ws:// transport sends tool payloads and responses in cleartext over the network.",
						suggestedFix: `Upgrade to encrypted WebSocket (wss://).`,
						file: cfg.filePath,
						serverName,
						keyName: "url.transport",
						evidenceMasked: `url=${safeUrl}`
					});
				}
			}
			const transport = String(server.transport || "").toLowerCase();
			if (transport === "tcp" || transport === "udp") findings.push({
				ruleId: "CAS-013",
				severity: "medium",
				title: `Unsupported or non-standard transport: "${transport}"`,
				whyItMatters: `MCP standard mandates stdio or SSE/HTTP transports. Direct raw ${transport.toUpperCase()} sockets lack TLS and authentication negotiation.`,
				suggestedFix: `Use stdio or HTTPS/SSE transport.`,
				file: cfg.filePath,
				serverName,
				keyName: "transport",
				evidenceMasked: `transport=${transport}`
			});
		}
	}
	return findings;
}
/**
* CAS-014: Stale or Missing Binary in Command
*/
function checkCas014(configFiles, ctx, skippedChecks) {
	const findings = [];
	if (!ctx?.fileExists) {
		if (skippedChecks) skippedChecks.push("CAS-014:disk-existence-check (no filesystem available)");
		return findings;
	}
	const fileExists = ctx.fileExists;
	const KNOWN_GLOBAL_BINARIES = /* @__PURE__ */ new Set([
		"node",
		"npx",
		"npm",
		"pnpm",
		"bun",
		"bunx",
		"deno",
		"python",
		"python3",
		"py",
		"pip",
		"pipx",
		"uv",
		"uvx",
		"docker",
		"docker-compose",
		"podman",
		"cargo",
		"rustc",
		"go",
		"java",
		"mvn",
		"gradle",
		"git",
		"bash",
		"sh",
		"zsh",
		"cmd",
		"cmd.exe",
		"powershell",
		"pwsh"
	]);
	for (const cfg of configFiles) {
		if (cfg.isEnvFile) continue;
		for (const [serverName, server] of Object.entries(cfg.servers)) {
			const cmd = server.command;
			if (!cmd || typeof cmd !== "string") continue;
			const trimmed = cmd.trim();
			const lower = trimmed.toLowerCase();
			if (KNOWN_GLOBAL_BINARIES.has(lower)) continue;
			if (trimmed.startsWith("./") || trimmed.startsWith("../") || trimmed.includes("/") || trimmed.includes("\\")) {
				const resolvedCmd = pureResolve(pureDirname(cfg.filePath), trimmed);
				if (!fileExists(trimmed) && !fileExists(resolvedCmd)) findings.push({
					ruleId: "CAS-014",
					severity: "low",
					title: `Command path does not exist on disk: "${trimmed}"`,
					whyItMatters: `The server specifies a relative or absolute executable path that cannot be found on disk.`,
					suggestedFix: `Ensure "${trimmed}" is built and available at the specified path.`,
					file: cfg.filePath,
					serverName,
					keyName: "command.exists",
					evidenceMasked: `command=${trimmed}`
				});
			}
		}
	}
	return findings;
}
/**
* CAS-015: Excessive Environment Variable Pass-Through
* Severity: Low, with configurable threshold (default: 25)
*/
function checkCas015(configFiles, maxEnvVars = 25) {
	const findings = [];
	for (const cfg of configFiles) {
		if (cfg.isEnvFile) continue;
		for (const [serverName, server] of Object.entries(cfg.servers)) {
			if (!server.env || typeof server.env !== "object") continue;
			const keys = Object.keys(server.env);
			if (keys.some((k) => k === "*" || k === "ALL" || server.env[k] === "*")) {
				findings.push({
					ruleId: "CAS-015",
					severity: "low",
					title: `Wildcard environment variable pass-through in server "${serverName}"`,
					whyItMatters: `Passing wildcard environment variables exposes parent system tokens and environment state to the MCP server process.`,
					suggestedFix: `Explicitly declare only the minimal environment variables needed by this tool.`,
					file: cfg.filePath,
					serverName,
					keyName: "env.wildcard",
					evidenceMasked: `env: wildcard * detected`
				});
				continue;
			}
			if (keys.length > maxEnvVars) findings.push({
				ruleId: "CAS-015",
				severity: "low",
				title: `Excessive environment variables configured (${keys.length} > ${maxEnvVars})`,
				whyItMatters: `Configuring ${keys.length} environment variables for "${serverName}" exceeds the threshold (${maxEnvVars}) and increases secret exposure surface.`,
				suggestedFix: `Trim environment variables to only those required by ${serverName}.`,
				file: cfg.filePath,
				serverName,
				keyName: "env.count",
				evidenceMasked: `env count: ${keys.length} (threshold: ${maxEnvVars})`
			});
		}
	}
	return findings;
}
/**
* Detect hidden Unicode characters (Requirement H):
* - Zero-width: U+200B..U+200D, U+2060, U+FEFF
* - Bidi control: U+202A..U+202E, U+2066..U+2069
* - Tag characters: U+E0000..U+E007F (surrogate pair \uDB40[\uDC00-\uDC7F])
*/
function detectHiddenUnicode(text) {
	for (let i = 0; i < text.length; i++) {
		const cp = text.codePointAt(i);
		if (cp > 65535) i++;
		if (cp >= 8203 && cp <= 8205 || cp === 8288 || cp === 65279) return {
			type: "Zero-Width Hidden Character",
			codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`
		};
		if (cp >= 8234 && cp <= 8238 || cp >= 8294 && cp <= 8297) return {
			type: "Bidirectional (Bidi) Override/Isolate Character",
			codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`
		};
		if (cp >= 917504 && cp <= 917631) return {
			type: "Unicode Tag Smuggling Character",
			codePoint: `U+${cp.toString(16).toUpperCase()}`
		};
	}
	return null;
}
/**
* CAS-016: AI Agent Rule Files & Config Descriptions
* - Hidden Unicode (zero-width, bidi, tag chars): High
* - Hardcoded secrets in rule files: High
* - Prompt injection / override phrases: Medium (marked as heuristic)
*/
function checkCas016(agentRuleFiles, configFiles = []) {
	const findings = [];
	const HEURISTIC_PROMPTS = [
		{
			pattern: /bypass(?:ing)?\s+(?:all\s+)?(?:security|safety|guardrails)/i,
			label: "Bypassing safety guardrails directive"
		},
		{
			pattern: /ignore\s+(?:all\s+)?previous\s+instructions/i,
			label: "Prompt injection override (ignore previous instructions)"
		},
		{
			pattern: /always\s+(?:run|execute)\s+(?:[a-z0-9_-]+\s+)*(?:commands|scripts|tools|code)\s+without\s+(?:asking|confirmation|prompt)/i,
			label: "Unrestricted automatic command execution directive"
		},
		{
			pattern: /auto[-_]?approve\s+(?:all|everything|\*)/i,
			label: "Wildcard auto-approve directive in AI instructions"
		},
		{
			pattern: /do\s+not\s+ask\s+(?:for\s+)?confirmation\s+before\s+(?:deleting|removing|executing)/i,
			label: "Suppression of user confirmation prompts"
		}
	];
	for (const ruleFile of agentRuleFiles) {
		const lines = ruleFile.rawContent.split(/\r?\n/);
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			const hidden = detectHiddenUnicode(line);
			if (hidden) findings.push({
				ruleId: "CAS-016",
				severity: "high",
				title: `Hidden Unicode character (${hidden.type} ${hidden.codePoint}) in ${ruleFile.fileName}`,
				whyItMatters: `File "${ruleFile.fileName}" contains invisible ${hidden.type} (${hidden.codePoint}) on line ${i + 1}, which can smuggle hidden prompt injection instructions past human code review.`,
				suggestedFix: `Strip all non-printable zero-width, bidirectional, and Unicode tag characters from ${ruleFile.fileName}.`,
				file: ruleFile.filePath,
				line: i + 1,
				keyName: `unicode.${hidden.codePoint}`,
				evidenceMasked: `line ${i + 1}: detected ${hidden.codePoint} (${hidden.type})`
			});
			const matched = detectSecrets(line);
			if (matched.length > 0) findings.push({
				ruleId: "CAS-016",
				severity: "high",
				title: `Hardcoded secret in AI rule file (${ruleFile.fileName})`,
				whyItMatters: `AI agents ingest ${ruleFile.fileName} into context on every interaction. Storing ${matched[0].patternName} here leaks credentials into LLM context logs.`,
				suggestedFix: "Remove the hardcoded secret from AI prompt guidelines and supply credentials via environment variables.",
				file: ruleFile.filePath,
				line: i + 1,
				keyName: `secret.line_${i + 1}`,
				evidenceMasked: matched[0].masked
			});
			for (const hp of HEURISTIC_PROMPTS) if (hp.pattern.test(line)) findings.push({
				ruleId: "CAS-016",
				severity: "medium",
				title: `[Heuristic] Suspicious instruction override in ${ruleFile.fileName}: ${hp.label}`,
				whyItMatters: `[Heuristic detection] Line ${i + 1} matches a phrase pattern ("${hp.label}") commonly used to weaken or bypass human-in-the-loop confirmation checks.`,
				suggestedFix: "Review this instruction manually and ensure destructive operations require user confirmation.",
				file: ruleFile.filePath,
				line: i + 1,
				keyName: `heuristic.${hp.label}`,
				evidenceMasked: `heuristic match: ${hp.label}`
			});
		}
	}
	for (const cfg of configFiles) {
		if (cfg.isEnvFile) continue;
		for (const [serverName, server] of Object.entries(cfg.servers)) {
			const fieldsToCheck = [
				["description", server.description],
				["command", server.command],
				...(server.args || []).map((a, idx) => [`args[${idx}]`, a])
			];
			for (const [fieldName, fieldVal] of fieldsToCheck) {
				if (typeof fieldVal !== "string") continue;
				const hidden = detectHiddenUnicode(fieldVal);
				if (hidden) findings.push({
					ruleId: "CAS-016",
					severity: "high",
					title: `Hidden Unicode character (${hidden.type} ${hidden.codePoint}) in server "${serverName}" ${fieldName}`,
					whyItMatters: `Configuration field "${fieldName}" of server "${serverName}" contains invisible ${hidden.type} (${hidden.codePoint}) that can disguise malicious commands or descriptions.`,
					suggestedFix: `Remove invisible Unicode characters (${hidden.codePoint}) from server "${serverName}".`,
					file: cfg.filePath,
					serverName,
					keyName: `${fieldName}.${hidden.codePoint}`,
					evidenceMasked: `${fieldName}: detected ${hidden.codePoint}`
				});
			}
		}
	}
	return findings;
}
// ../castov-core/dist/audit/formatters/json.js
function formatJsonOutput(result) {
	return JSON.stringify(result, null, 2);
}
// ../castov-core/dist/audit/formatters/md.js
function formatMarkdownReport(result, clientName) {
	const lines = [];
	const targetTitle = clientName ? `Security Audit Report for ${clientName}` : "AI Agent & MCP Security Audit Report";
	lines.push(`# ${targetTitle}`);
	lines.push("");
	lines.push(`**Generated by**: Castov CLI v${result.toolVersion} (100% Offline & Deterministic)  `);
	lines.push(`**Audit Date**: ${result.scannedAt}  `);
	lines.push(`**Target Scope**: \`${result.targetPath}\`  `);
	lines.push("");
	lines.push("## 1. Executive Summary");
	lines.push("");
	lines.push("This security audit evaluates Model Context Protocol (MCP) server configurations, AI coding agent privileges, and credential exposure across local and project-level configuration assets.");
	lines.push("");
	lines.push("| Severity Level | Count |");
	lines.push("| --- | :---: |");
	lines.push(`| **Critical** | ${result.counts.critical} |`);
	lines.push(`| **High** | ${result.counts.high} |`);
	lines.push(`| **Medium** | ${result.counts.medium} |`);
	lines.push(`| **Low** | ${result.counts.low} |`);
	lines.push(`| **Informational** | ${result.counts.info} |`);
	lines.push("");
	lines.push("### Top Key Risks Identified");
	const topRisks = result.findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 3);
	if (topRisks.length > 0) topRisks.forEach((r, idx) => {
		lines.push(`${idx + 1}. **${r.title}**: ${r.whyItMatters}`);
	});
	else if (result.findings.length > 0) lines.push(`1. **${result.findings[0].title}**: ${result.findings[0].whyItMatters}`);
	else lines.push("✓ No critical or high-severity vulnerabilities were identified during this audit scan.");
	lines.push("");
	lines.push("## 2. Audit Scope");
	lines.push("");
	lines.push("- **Total Files Scanned**: " + result.filesScanned.length);
	lines.push("- **Target Directory**: `" + result.targetPath + "`");
	lines.push("- **Excluded Assets**: Default exclusions applied (`node_modules/`, `.git/`, `dist/`, `build/`, `coverage/`, and binaries >2MB).");
	lines.push("");
	lines.push("<details><summary>Click to view list of audited configuration files</summary>");
	lines.push("");
	for (const f of result.filesScanned) lines.push(`- \`${f}\``);
	lines.push("</details>");
	lines.push("");
	lines.push("## 3. Findings Overview");
	lines.push("");
	if (result.findings.length === 0) lines.push("Zero findings reported. All scanned configurations adhere to deterministic security baselines.");
	else {
		lines.push("| ID | Severity | Title | File / Server |");
		lines.push("| --- | --- | --- | --- |");
		for (const f of result.findings) lines.push(`| **${f.ruleId}** | \`${f.severity.toUpperCase()}\` | ${f.title} | \`${f.file}\` ${f.serverName ? `(${f.serverName})` : ""} |`);
	}
	lines.push("");
	if (result.findings.length > 0) {
		lines.push("## 4. Detailed Findings & Masked Evidence");
		lines.push("");
		for (const f of result.findings) {
			lines.push(`### [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.title}`);
			lines.push(`- **Location**: \`${f.file}\`${f.serverName ? ` (Server: **${f.serverName}**)` : ""}`);
			lines.push(`- **Why it Matters**: ${f.whyItMatters}`);
			if (f.evidenceMasked) lines.push(`- **Masked Evidence**: \`${f.evidenceMasked}\``);
			lines.push(`- **Remediation**: ${f.suggestedFix}`);
			lines.push("");
		}
	}
	lines.push("## 5. Prioritized Remediation Checklist");
	lines.push("");
	if (result.findings.length === 0) lines.push("- [x] Baseline verified. Continue monitoring in CI/CD pipeline.");
	else for (const f of result.findings) lines.push(`- [ ] **[${f.severity.toUpperCase()}]** Fix \`${f.ruleId}\` in \`${f.file}\`: ${f.suggestedFix}`);
	lines.push("");
	lines.push("## 6. Methodology & Security Disclaimer");
	lines.push("");
	lines.push("> **Disclaimer**: This audit report evaluates static configurations, environment variables, and MCP declaration parameters using offline deterministic static analysis rules. Static configuration auditing significantly reduces exposure to supply-chain attacks, credential exfiltration, and privilege escalation, but does not guarantee the complete absence of unknown vulnerabilities or runtime zero-days. Continuous verification in CI/CD pipelines is strongly recommended.");
	lines.push("");
	return lines.join("\n");
}
// ../castov-core/dist/audit/formatters/sarif.js
function severityToSarifLevel(sev) {
	switch (sev) {
		case "critical":
		case "high": return "error";
		case "medium": return "warning";
		default: return "note";
	}
}
/**
* Converts a file path into a relative, forward-slash, URI-encoded path suitable for SARIF
* and GitHub Code Scanning (never contains file:///, drive letters, leading '/', or '..').
*/
function toSafeRelativeUri(targetDir, filePath) {
	let rel = pureRelative(targetDir, filePath).replace(/\\/g, "/");
	rel = rel.replace(/^(?:\.\/)+/, "");
	if (!rel || rel.startsWith("..") || rel.startsWith("/") || /^[a-zA-Z]:/.test(rel) || rel.toLowerCase().startsWith("file:")) rel = `external-configs/${filePath.replace(/^file:\/*/i, "").replace(/^[a-zA-Z]:[\\/]?/, "").replace(/\\/g, "/").split("/").filter((s) => s && s !== "." && s !== "..").slice(-3).join("/") || pureBasename(filePath) || "config.json"}`;
	return rel.split("/").filter(Boolean).map((seg) => encodeURIComponent(seg)).join("/");
}
function formatSarifOutput(result) {
	const targetDir = result.targetPath;
	const ruleEntries = Object.entries(ALL_RULES_METADATA);
	const ruleIndexMap = /* @__PURE__ */ new Map();
	const rulesList = ruleEntries.map(([rId, rDef], idx) => {
		ruleIndexMap.set(rId, idx);
		return {
			id: rDef.id,
			name: rDef.title.replace(/[^a-zA-Z0-9]/g, ""),
			shortDescription: { text: rDef.title },
			fullDescription: { text: rDef.whyItMatters },
			help: {
				text: rDef.suggestedFix,
				markdown: `### Remediation\n\n${rDef.suggestedFix}\n\n**Impact**: ${rDef.whyItMatters}`
			},
			defaultConfiguration: { level: severityToSarifLevel(rDef.severity) },
			properties: {
				precision: "high",
				"security-severity": Number(rDef.securitySeverity ?? 5).toFixed(1),
				tags: [
					"security",
					"ai-agents",
					"mcp",
					"credentials"
				]
			}
		};
	});
	const sarifResults = result.findings.map((f) => {
		const uri = toSafeRelativeUri(targetDir, f.file);
		const ruleIndex = ruleIndexMap.get(f.ruleId) ?? 0;
		return {
			ruleId: f.ruleId,
			ruleIndex,
			level: severityToSarifLevel(f.severity),
			message: { text: `${f.title}. ${f.whyItMatters}` },
			locations: [{ physicalLocation: {
				artifactLocation: {
					uri,
					uriBaseId: "%SRCROOT%"
				},
				region: {
					startLine: f.line && f.line > 0 ? f.line : 1,
					startColumn: f.column && f.column > 0 ? f.column : 1
				}
			} }],
			partialFingerprints: { primaryLocationLineHash: f.fingerprint || `${f.ruleId}|${uri}|${f.serverName || ""}|${f.keyName || ""}` },
			properties: {
				severity: f.severity,
				evidenceMasked: f.evidenceMasked,
				suggestedFix: f.suggestedFix,
				...f.serverName ? { serverName: f.serverName } : {}
			}
		};
	});
	const sarifLog = {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [{
			tool: { driver: {
				name: "Castov",
				version: result.toolVersion,
				informationUri: "https://castov.com",
				rules: rulesList
			} },
			results: sarifResults
		}]
	};
	return JSON.stringify(sarifLog, null, 2);
}
// ../castov-core/dist/audit/formatters/text.js
function formatTextOutput(result, useColor = true) {
	const lines = [];
	const red = (s) => useColor ? `\x1b[31m${s}\x1b[0m` : s;
	const yellow = (s) => useColor ? `\x1b[33m${s}\x1b[0m` : s;
	const blue = (s) => useColor ? `\x1b[34m${s}\x1b[0m` : s;
	const gray = (s) => useColor ? `\x1b[90m${s}\x1b[0m` : s;
	const bold = (s) => useColor ? `\x1b[1m${s}\x1b[0m` : s;
	const green = (s) => useColor ? `\x1b[32m${s}\x1b[0m` : s;
	lines.push(bold("🛡️ Castov Local MCP & AI Agent Security Audit"));
	lines.push(gray(`Scanned ${result.filesScanned.length} configuration file(s) across "${result.targetPath}"`));
	lines.push("");
	const countParts = [
		result.counts.critical > 0 ? red(`${result.counts.critical} Critical`) : "0 Critical",
		result.counts.high > 0 ? yellow(`${result.counts.high} High`) : "0 High",
		result.counts.medium > 0 ? blue(`${result.counts.medium} Medium`) : "0 Medium",
		result.counts.low > 0 ? gray(`${result.counts.low} Low`) : "0 Low",
		result.counts.info > 0 ? gray(`${result.counts.info} Info`) : "0 Info"
	];
	lines.push(`Summary: ${countParts.join(" | ")}`);
	lines.push("");
	if (result.findings.length === 0) {
		lines.push(green("✓ Zero security vulnerabilities detected in AI agent and MCP configurations."));
		return lines.join("\n");
	}
	lines.push(bold("Detected Findings:"));
	for (const f of result.findings) {
		let badge = `[${f.severity.toUpperCase()}]`;
		if (f.severity === "critical") badge = red(bold(badge));
		else if (f.severity === "high") badge = yellow(bold(badge));
		else if (f.severity === "medium") badge = blue(badge);
		else badge = gray(badge);
		lines.push(`  ${badge} ${bold(f.ruleId)}: ${f.title}`);
		lines.push(`     File: ${gray(f.file)}${f.serverName ? ` (Server: ${f.serverName})` : ""}`);
		if (f.evidenceMasked) lines.push(`     Evidence: ${gray(f.evidenceMasked)}`);
		lines.push(`     Fix: ${f.suggestedFix}`);
		lines.push("");
	}
	return lines.join("\n");
}
// ../castov-core/dist/audit/formatters/index.js
function formatAuditOutput(result, options = {}) {
	const format = options.format || "text";
	if (format === "json") return formatJsonOutput(result);
	if (format === "sarif") return formatSarifOutput(result);
	if (format === "md") return formatMarkdownReport(result, options.clientName);
	return formatTextOutput(result, options.useColor ?? true);
}
// ../castov-core/dist/audit/core-engine.js
const SEVERITY_WEIGHT = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4
};
const FAIL_ON_THRESHOLDS = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	none: -1
};
/**
* Compute finding fingerprint strictly from:
* ruleId + relativePath (with '/' separators) + serverName + keyName
* Contains NO secret value, NO hash of a secret value, and NO line number (Requirement F).
*/
function computeFindingFingerprint(targetPath, f) {
	const rel = toSafeRelativeUri(targetPath, f.file);
	const sName = f.serverName || "";
	const kName = f.keyName || "";
	return `${f.ruleId}|${rel}|${sName}|${kName}`;
}
function runAuditCore(files, options, baseline = { status: "not_requested" }, runtime) {
	const { targetPath } = files;
	const ignoreSet = new Set((options.ignoreRules || []).map((r) => r.toUpperCase()));
	const maxEnvVars = options.maxEnvVars ?? 25;
	const toolVersion = options.toolVersion ?? "1.6.0";
	const skippedChecks = [];
	const rawFindings = [];
	for (const pErr of files.parseErrors) if (!ignoreSet.has(pErr.ruleId.toUpperCase())) rawFindings.push(pErr);
	for (const cfg of files.configFiles) {
		if (cfg.isEnvFile) continue;
		const fileFindings = runRulesCas001To007(cfg);
		for (const f of fileFindings) if (!ignoreSet.has(f.ruleId.toUpperCase())) rawFindings.push(f);
	}
	const cas008Findings = checkCas008(files.envFiles, files.hasCursorIgnore, files.cursorIgnoreContent, {
		hasClaudeIgnore: files.hasClaudeIgnore,
		claudeIgnorePath: files.claudeIgnorePath,
		claudeSettings: files.claudeSettings
	});
	for (const f of cas008Findings) if (!ignoreSet.has("CAS-008")) rawFindings.push(f);
	const cas009Findings = checkCas009(files.envFiles, files.hasGitignore, files.gitignoreContent);
	for (const f of cas009Findings) if (!ignoreSet.has("CAS-009")) rawFindings.push(f);
	const cas010Findings = checkCas010(files.configFiles);
	for (const f of cas010Findings) if (!ignoreSet.has("CAS-010")) rawFindings.push(f);
	const cas013Findings = checkCas013(files.configFiles);
	for (const f of cas013Findings) if (!ignoreSet.has("CAS-013")) rawFindings.push(f);
	const cas014Findings = checkCas014(files.configFiles, runtime, skippedChecks);
	for (const f of cas014Findings) if (!ignoreSet.has("CAS-014")) rawFindings.push(f);
	const cas015Findings = checkCas015(files.configFiles, maxEnvVars);
	for (const f of cas015Findings) if (!ignoreSet.has("CAS-015")) rawFindings.push(f);
	const cas016Findings = checkCas016(files.agentRuleFiles, files.configFiles);
	for (const f of cas016Findings) if (!ignoreSet.has("CAS-016")) rawFindings.push(f);
	const currentServersMap = buildBaselineServersMap(files.configFiles, targetPath, runtime);
	let baselineFingerprints = /* @__PURE__ */ new Set();
	let baselineServersMap;
	if (baseline.status === "loaded") {
		if (Array.isArray(baseline.data.fingerprints)) baselineFingerprints = new Set(baseline.data.fingerprints);
		if (baseline.data.servers && typeof baseline.data.servers === "object") baselineServersMap = baseline.data.servers;
	}
	let totalSuppressed = 0;
	for (const f of rawFindings) {
		f.fingerprint = computeFindingFingerprint(targetPath, f);
		if (baselineFingerprints.has(f.fingerprint)) {
			f.isBaselineSuppressed = true;
			totalSuppressed++;
		}
	}
	if (baselineServersMap && !ignoreSet.has("CAS-011")) {
		const cas011Findings = checkCas011(currentServersMap, baselineServersMap, targetPath);
		for (const f of cas011Findings) {
			f.fingerprint = computeFindingFingerprint(targetPath, f);
			rawFindings.push(f);
		}
	}
	const newBaseline = {
		schemaVersion: "1.0.0",
		createdAt: options.baselineCreatedAt,
		targetPath: ".",
		fingerprints: Array.from(new Set(rawFindings.map((f) => f.fingerprint || ""))).sort(),
		servers: currentServersMap
	};
	rawFindings.sort((a, b) => {
		const sevDiff = SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity];
		if (sevDiff !== 0) return sevDiff;
		const fileDiff = a.file.localeCompare(b.file);
		if (fileDiff !== 0) return fileDiff;
		const ruleDiff = a.ruleId.localeCompare(b.ruleId);
		if (ruleDiff !== 0) return ruleDiff;
		return a.title.localeCompare(b.title);
	});
	const counts = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0
	};
	for (const f of rawFindings) counts[f.severity]++;
	const failThresholdName = options.failOn || "high";
	const failThreshold = FAIL_ON_THRESHOLDS[failThresholdName] ?? 1;
	let hasFailingFindings = false;
	if (failThreshold !== -1) {
		for (const f of rawFindings) if (!f.isBaselineSuppressed && SEVERITY_WEIGHT[f.severity] <= failThreshold) {
			hasFailingFindings = true;
			break;
		}
	}
	const exitCode = hasFailingFindings ? 1 : 0;
	return {
		result: {
			schemaVersion: "1.0.0",
			toolVersion,
			scannedAt: options.scannedAt,
			targetPath,
			filesScanned: [...files.scannedFiles].sort(),
			findings: rawFindings,
			counts,
			exitCode,
			...skippedChecks.length > 0 ? { skippedChecks } : {},
			...baseline.status !== "not_requested" ? { baselineSummary: {
				totalSuppressed,
				newFindings: rawFindings.length - totalSuppressed
			} } : {}
		},
		newBaseline
	};
}
// dist-ts/jsonc.js
/**
* String-aware JSON with Comments (JSONC) parser.
* Strips single-line (//) and multi-line (/* * /) comments and trailing commas
* only outside quoted JSON strings, preserving string contents verbatim.
*/
function parseJsonc(text) {
	if (!text || text.trim() === "") return {
		data: null,
		error: "Empty content"
	};
	try {
		let insideString = false;
		let escape = false;
		let noComments = "";
		for (let i = 0; i < text.length; i++) {
			const char = text[i];
			const next = text[i + 1];
			if (insideString) {
				noComments += char;
				if (escape) escape = false;
				else if (char === "\\") escape = true;
				else if (char === "\"") insideString = false;
				continue;
			}
			if (char === "\"") {
				insideString = true;
				noComments += char;
				continue;
			}
			if (char === "/" && next === "/") {
				while (i < text.length && text[i] !== "\n") i++;
				noComments += "\n";
				continue;
			}
			if (char === "/" && next === "*") {
				i += 2;
				while (i < text.length - 1 && !(text[i] === "*" && text[i + 1] === "/")) {
					if (text[i] === "\n") noComments += "\n";
					i++;
				}
				i++;
				continue;
			}
			noComments += char;
		}
		let cleaned = "";
		insideString = false;
		escape = false;
		for (let i = 0; i < noComments.length; i++) {
			const char = noComments[i];
			if (insideString) {
				cleaned += char;
				if (escape) escape = false;
				else if (char === "\\") escape = true;
				else if (char === "\"") insideString = false;
				continue;
			}
			if (char === "\"") {
				insideString = true;
				cleaned += char;
				continue;
			}
			if (char === ",") {
				let j = i + 1;
				while (j < noComments.length && /\s/.test(noComments[j])) j++;
				if (noComments[j] === "]" || noComments[j] === "}") continue;
			}
			cleaned += char;
		}
		return { data: JSON.parse(cleaned) };
	} catch (err) {
		return {
			data: null,
			error: err instanceof Error ? err.message : String(err)
		};
	}
}
// dist-ts/path-guard.js
function normalizeForComparison(p) {
	return process.platform === "win32" ? p.toLowerCase() : p;
}
function isPathInside(rootReal, candidateReal) {
	const normRoot = normalizeForComparison(rootReal);
	const normCandidate = normalizeForComparison(candidateReal);
	if (normCandidate === normRoot) return true;
	const rel = (0, node_path.relative)(normRoot, normCandidate);
	return rel !== "" && !rel.startsWith("..") && !(0, node_path.isAbsolute)(rel);
}
function resolveWorkspaceRoot(rawRoot) {
	return (0, node_fs.realpathSync)((0, node_path.resolve)(rawRoot));
}
/**
* Resolves an existing path (such as scan target or baseline file) inside rootReal.
* Rejects symbolic links and any canonical path escaping rootReal.
*/
function resolveContainedExistingPath(rootReal, userPath, options = {}) {
	const candidate = (0, node_path.resolve)(rootReal, userPath);
	if (!(0, node_fs.existsSync)(candidate)) {
		if (!options.allowMissing) throw new Error(`Path does not exist: ${userPath}`);
		const ancestor = findNearestExistingAncestor(candidate);
		if (!isPathInside(rootReal, (0, node_fs.realpathSync)(ancestor))) throw new Error(`Path escapes workspace boundary: ${userPath}`);
		return candidate;
	}
	if ((0, node_fs.lstatSync)(candidate).isSymbolicLink()) throw new Error(`Symbolic link is not permitted for path: ${userPath}`);
	const realCandidate = (0, node_fs.realpathSync)(candidate);
	if (!isPathInside(rootReal, realCandidate)) throw new Error(`Path escapes workspace boundary: ${userPath}`);
	return realCandidate;
}
function findNearestExistingAncestor(targetPath) {
	let current = targetPath;
	while (!(0, node_fs.existsSync)(current)) {
		const parent = (0, node_path.dirname)(current);
		if (parent === current) break;
		current = parent;
	}
	return current;
}
/**
* Validates that a write destination stays inside rootReal and does not traverse or overwrite symlinks.
*/
function resolveContainedWritePath(rootReal, userPath) {
	const candidate = (0, node_path.resolve)(rootReal, userPath);
	if ((0, node_fs.existsSync)(candidate)) {
		const lst = (0, node_fs.lstatSync)(candidate);
		if (lst.isSymbolicLink()) throw new Error(`Refusing to write to symbolic link: ${userPath}`);
		if (lst.isDirectory()) throw new Error(`Refusing to overwrite directory as report file: ${userPath}`);
	}
	let check = (0, node_fs.existsSync)(candidate) ? candidate : findNearestExistingAncestor(candidate);
	if (!isPathInside(rootReal, (0, node_fs.realpathSync)(check))) throw new Error(`Write path escapes workspace boundary: ${userPath}`);
	const relFromRoot = (0, node_path.relative)(rootReal, candidate);
	if (relFromRoot.startsWith("..") || (0, node_path.isAbsolute)(relFromRoot)) throw new Error(`Write path escapes workspace boundary: ${userPath}`);
	const parts = relFromRoot.split(node_path.sep).filter(Boolean);
	let cursor = rootReal;
	for (const part of parts) {
		cursor = (0, node_path.resolve)(cursor, part);
		if ((0, node_fs.existsSync)(cursor) && (0, node_fs.lstatSync)(cursor).isSymbolicLink()) throw new Error(`Symbolic link segment not permitted in write path: ${userPath}`);
	}
	return candidate;
}
/**
* Stages all report writes via temporary sibling files and atomically renames them.
* If any write or rename fails, cleans up only temporary files and newly created outputs
* from this run, never deleting or corrupting pre-existing user files.
*/
function atomicWriteFiles(items) {
	const staged = [];
	const newlyCreatedTargets = [];
	try {
		for (const item of items) {
			const parentDir = (0, node_path.dirname)(item.targetPath);
			(0, node_fs.mkdirSync)(parentDir, { recursive: true });
			const existedBefore = (0, node_fs.existsSync)(item.targetPath);
			const tmpPath = `${item.targetPath}.castov-tmp-${(0, node_crypto.randomUUID)()}`;
			const fd = (0, node_fs.openSync)(tmpPath, "wx", 384);
			try {
				(0, node_fs.writeSync)(fd, item.content, void 0, "utf8");
				(0, node_fs.fsyncSync)(fd);
			} finally {
				(0, node_fs.closeSync)(fd);
			}
			staged.push({
				tmpPath,
				targetPath: item.targetPath,
				existedBefore
			});
		}
		for (const entry of staged) {
			(0, node_fs.renameSync)(entry.tmpPath, entry.targetPath);
			if (!entry.existedBefore) newlyCreatedTargets.push(entry.targetPath);
		}
	} catch (err) {
		for (const entry of staged) try {
			if ((0, node_fs.existsSync)(entry.tmpPath)) (0, node_fs.unlinkSync)(entry.tmpPath);
		} catch {}
		for (const created of newlyCreatedTargets) try {
			if ((0, node_fs.existsSync)(created)) (0, node_fs.unlinkSync)(created);
		} catch {}
		throw err;
	}
}
// dist-ts/sanitize.js
const CONTROL_AND_BIDI_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
function stripControlAndBidi(input) {
	return input.replace(CONTROL_AND_BIDI_RE, "");
}
function escapeWorkflowData(input) {
	return stripControlAndBidi(input).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeWorkflowProperty(input) {
	return escapeWorkflowData(input).replace(/:/g, "%3A").replace(/,/g, "%2C");
}
function sanitizeMarkdownText(input) {
	return stripControlAndBidi(input).replace(/[\r\n\t]+/g, " ").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/`/g, "\\`").replace(/\|/g, "\\|").replace(/\[/g, "\\[").replace(/\]/g, "\\]").replace(/\(/g, "\\(").replace(/\)/g, "\\)").trim();
}
function toWorkspaceRelativePosix(workspaceReal, filePath) {
	return (0, node_path.relative)(workspaceReal, filePath).replace(/\\/g, "/") || ".";
}
// dist-ts/discovery.js
const IGNORED_DIRS = /* @__PURE__ */ new Set([
	"node_modules",
	".git",
	".next",
	"dist",
	"build",
	"coverage",
	".vercel",
	".turbo",
	"target",
	"vendor"
]);
const MCP_FILE_NAMES = /* @__PURE__ */ new Set([
	".mcp.json",
	"mcp.json",
	"claude_desktop_config.json",
	"cline_mcp_settings.json",
	"mcp_config.json"
]);
const AGENT_RULE_FILES = /* @__PURE__ */ new Set([
	".cursorrules",
	"CLAUDE.md",
	"AGENTS.md"
]);
function extractServers(parsed) {
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
	const obj = parsed;
	const rawServers = obj.mcpServers || obj.servers || obj.mcp?.servers || obj.context_servers;
	if (!rawServers || typeof rawServers !== "object" || Array.isArray(rawServers)) return {};
	const servers = {};
	for (const [name, val] of Object.entries(rawServers)) if (val && typeof val === "object" && !Array.isArray(val)) servers[name] = {
		name,
		...val
	};
	return servers;
}
function inferClientName(relPosix) {
	if (relPosix.includes(".cursor/")) return "Cursor";
	if (relPosix.includes(".vscode/")) return "VS Code";
	if (relPosix.includes(".zed/")) return "Zed";
	if (relPosix.includes("claude")) return "Claude";
	return "MCP";
}
function discoverActionFiles(workspaceReal, targetReal, limits = {}) {
	const maxDepth = Math.min(Math.max(1, limits.maxDepth ?? 6), 10);
	const maxFiles = Math.max(1, limits.maxFiles ?? 5e3);
	const maxFileBytes = Math.max(1024, limits.maxFileBytes ?? 1048576);
	const maxTotalBytes = Math.max(1024, limits.maxTotalBytes ?? 10485760);
	const configFiles = [];
	const agentRuleFiles = [];
	const envFiles = [];
	const claudeSettings = [];
	const scannedFiles = [];
	const parseErrors = [];
	const skippedFiles = [];
	let hasGitignore = false;
	let gitignoreContent = "";
	let hasCursorIgnore = false;
	let cursorIgnoreContent = "";
	let hasClaudeIgnore = false;
	let claudeIgnorePath;
	let visitedEntries = 0;
	let totalBytesRead = 0;
	let fileLimitRecorded = false;
	function safeReadText(absPath, relPosix) {
		try {
			const lst = (0, node_fs.lstatSync)(absPath);
			if (lst.isSymbolicLink()) {
				skippedFiles.push({
					path: relPosix,
					reason: "symlink-skipped"
				});
				return null;
			}
			if (lst.size > maxFileBytes) {
				skippedFiles.push({
					path: relPosix,
					reason: "size-limit"
				});
				return null;
			}
			if (totalBytesRead + lst.size > maxTotalBytes) {
				skippedFiles.push({
					path: relPosix,
					reason: "total-size-limit"
				});
				return null;
			}
			const content = (0, node_fs.readFileSync)(absPath, "utf8");
			totalBytesRead += lst.size;
			return content;
		} catch {
			skippedFiles.push({
				path: relPosix,
				reason: "permission-denied"
			});
			return null;
		}
	}
	function walk(dir, depth) {
		if (visitedEntries >= maxFiles) return;
		let entries;
		try {
			entries = (0, node_fs.readdirSync)(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
		} catch {
			skippedFiles.push({
				path: toWorkspaceRelativePosix(workspaceReal, dir),
				reason: "permission-denied"
			});
			return;
		}
		for (const entry of entries) {
			if (visitedEntries >= maxFiles) {
				if (!fileLimitRecorded) {
					fileLimitRecorded = true;
					skippedFiles.push({
						path: toWorkspaceRelativePosix(workspaceReal, dir),
						reason: "file-count-limit"
					});
				}
				return;
			}
			const fullPath = (0, node_path.join)(dir, entry.name);
			const relPosix = toWorkspaceRelativePosix(workspaceReal, fullPath);
			let lst;
			try {
				lst = (0, node_fs.lstatSync)(fullPath);
			} catch {
				skippedFiles.push({
					path: relPosix,
					reason: "permission-denied"
				});
				continue;
			}
			if (lst.isSymbolicLink()) {
				skippedFiles.push({
					path: relPosix,
					reason: "symlink-skipped"
				});
				continue;
			}
			if (!isPathInside(workspaceReal, fullPath)) {
				skippedFiles.push({
					path: relPosix,
					reason: "symlink-skipped"
				});
				continue;
			}
			if (lst.isDirectory()) {
				if (IGNORED_DIRS.has(entry.name)) continue;
				if (depth >= maxDepth) {
					skippedFiles.push({
						path: relPosix,
						reason: "depth-limit"
					});
					continue;
				}
				walk(fullPath, depth + 1);
				continue;
			}
			if (!lst.isFile()) continue;
			visitedEntries++;
			const name = entry.name;
			if (name === ".gitignore" && depth === 0) {
				const txt = safeReadText(fullPath, relPosix);
				if (txt !== null) {
					hasGitignore = true;
					gitignoreContent = txt;
				}
				continue;
			}
			if (name === ".cursorignore" && depth === 0) {
				const txt = safeReadText(fullPath, relPosix);
				if (txt !== null) {
					hasCursorIgnore = true;
					cursorIgnoreContent = txt;
				}
				continue;
			}
			if (name === ".claudeignore" && depth === 0) {
				hasClaudeIgnore = true;
				claudeIgnorePath = fullPath;
				continue;
			}
			if (name === ".env" || name.startsWith(".env.") && !name.endsWith(".example") && !name.endsWith(".template")) {
				const txt = safeReadText(fullPath, relPosix);
				if (txt !== null) {
					scannedFiles.push(fullPath);
					envFiles.push({
						filePath: fullPath,
						fileName: name,
						rawContent: txt
					});
				}
				continue;
			}
			if (relPosix.endsWith(".claude/settings.json") || relPosix.endsWith(".claude/settings.local.json")) {
				const txt = safeReadText(fullPath, relPosix);
				if (txt !== null) {
					scannedFiles.push(fullPath);
					const parsed = parseJsonc(txt);
					if (parsed.error || !parsed.data) parseErrors.push({
						ruleId: "CAS-012",
						severity: "info",
						title: `Malformed configuration file: ${name}`,
						whyItMatters: "Unparseable configuration files prevent full security inspection.",
						suggestedFix: "Fix JSON/JSONC syntax errors in the configuration file.",
						file: fullPath,
						keyName: "parse"
					});
					else {
						const perms = parsed.data.permissions;
						const denyRules = Array.isArray(perms?.deny) ? perms.deny.filter((d) => typeof d === "string") : [];
						claudeSettings.push({
							filePath: fullPath,
							scope: "project",
							denyRules
						});
					}
				}
				continue;
			}
			if (AGENT_RULE_FILES.has(name) || relPosix.includes(".cursor/rules/") && name.endsWith(".mdc")) {
				const txt = safeReadText(fullPath, relPosix);
				if (txt !== null) {
					scannedFiles.push(fullPath);
					agentRuleFiles.push({
						filePath: fullPath,
						fileName: name,
						rawContent: txt
					});
				}
				continue;
			}
			if (MCP_FILE_NAMES.has(name) || relPosix.endsWith(".vscode/mcp.json") || relPosix.endsWith(".zed/settings.json") || relPosix.endsWith(".cursor/mcp.json")) {
				const txt = safeReadText(fullPath, relPosix);
				if (txt !== null) {
					scannedFiles.push(fullPath);
					const parsed = parseJsonc(txt);
					if (parsed.error || !parsed.data) parseErrors.push({
						ruleId: "CAS-012",
						severity: "info",
						title: `Malformed configuration file: ${(0, node_path.basename)(fullPath)}`,
						whyItMatters: "Unparseable configuration files prevent full MCP server security inspection.",
						suggestedFix: "Fix JSON/JSONC syntax errors in the configuration file.",
						file: fullPath,
						keyName: "parse"
					});
					else configFiles.push({
						filePath: fullPath,
						clientName: inferClientName(relPosix),
						scope: "project",
						servers: extractServers(parsed.data),
						rawContent: txt,
						isEnvFile: false
					});
				}
			}
		}
	}
	walk(targetReal, 0);
	return {
		inputFiles: {
			targetPath: targetReal,
			configFiles,
			agentRuleFiles,
			envFiles,
			hasGitignore,
			gitignoreContent,
			hasCursorIgnore,
			cursorIgnoreContent,
			hasClaudeIgnore,
			claudeIgnorePath,
			claudeSettings,
			scannedFiles,
			parseErrors
		},
		skippedFiles
	};
}
function loadBaselineState(baselinePath) {
	if (!baselinePath) return { status: "not_requested" };
	if (!(0, node_fs.existsSync)(baselinePath)) return { status: "missing_file" };
	try {
		const content = (0, node_fs.readFileSync)(baselinePath, "utf8");
		const parsed = JSON.parse(content);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { status: "invalid_or_empty" };
		return {
			status: "loaded",
			data: parsed
		};
	} catch {
		return { status: "invalid_or_empty" };
	}
}
// dist-ts/github.js
function writeGitHubOutputs(outputs) {
	const outputPath = process.env.GITHUB_OUTPUT;
	if (!outputPath) return;
	const lines = [];
	for (const [key, value] of Object.entries(outputs)) {
		const delimiter = `ghadelimiter_${(0, node_crypto.randomUUID)().replace(/-/g, "")}`;
		lines.push(`${key}<<${delimiter}\n${value}\n${delimiter}\n`);
	}
	(0, node_fs.appendFileSync)(outputPath, lines.join(""), "utf8");
}
function formatAnnotationLine(workspaceReal, finding) {
	const level = finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "notice";
	const propFile = escapeWorkflowProperty(toWorkspaceRelativePosix(workspaceReal, finding.file));
	const propTitle = escapeWorkflowProperty(`${finding.ruleId} (${finding.severity})`);
	return `::${level} file=${propFile}${typeof finding.line === "number" && finding.line > 0 ? `,line=${finding.line}` : ""},title=${propTitle}::${escapeWorkflowData(`${finding.ruleId}: ${finding.title}`)}`;
}
function emitWorkflowAnnotations(workspaceReal, findings) {
	const active = findings.filter((f) => !f.isBaselineSuppressed).slice(0, 50);
	for (const finding of active) process.stdout.write(`${formatAnnotationLine(workspaceReal, finding)}\n`);
}
function buildStepSummaryMarkdown(workspaceReal, result, auditStatus, skippedFiles) {
	const lines = [];
	lines.push("## Castov AI & MCP Security Audit");
	lines.push("");
	if (auditStatus === "incomplete") {
		lines.push(`> **INCOMPLETE SCAN**: Discovery limits or filesystem skips prevented full coverage (${skippedFiles.length} item(s) skipped). Do not treat this run as a clean scan.`);
		lines.push("");
	} else if (auditStatus === "failed") {
		lines.push("> **FAILED**: The audit encountered a fatal error before completing.");
		lines.push("");
	}
	lines.push(`- **Audit Status**: \`${auditStatus}\``);
	lines.push(`- **Files Scanned**: ${result.filesScanned.length}`);
	lines.push(`- **Skipped Items**: ${skippedFiles.length}`);
	lines.push("");
	lines.push("| Critical | High | Medium | Low | Info |");
	lines.push("| :---: | :---: | :---: | :---: | :---: |");
	lines.push(`| ${result.counts.critical} | ${result.counts.high} | ${result.counts.medium} | ${result.counts.low} | ${result.counts.info} |`);
	lines.push("");
	const active = result.findings.filter((f) => !f.isBaselineSuppressed);
	if (active.length === 0 && auditStatus === "complete") {
		lines.push("No security findings detected.");
		lines.push("");
	} else if (active.length > 0) {
		lines.push("### Findings");
		lines.push("");
		lines.push("| Severity | Rule | File | Summary |");
		lines.push("| :--- | :--- | :--- | :--- |");
		for (const f of active.slice(0, 50)) {
			const rel = sanitizeMarkdownText(toWorkspaceRelativePosix(workspaceReal, f.file));
			const title = sanitizeMarkdownText(f.title);
			lines.push(`| ${f.severity.toUpperCase()} | ${sanitizeMarkdownText(f.ruleId)} | \`${rel}\` | ${title} |`);
		}
		lines.push("");
	}
	if (skippedFiles.length > 0) {
		lines.push("### Skipped Coverage");
		lines.push("");
		lines.push("| Path | Reason |");
		lines.push("| :--- | :--- |");
		for (const item of skippedFiles.slice(0, 25)) lines.push(`| \`${sanitizeMarkdownText(item.path)}\` | ${sanitizeMarkdownText(item.reason)} |`);
		lines.push("");
	}
	return lines.join("\n");
}
function writeStepSummary(workspaceReal, result, auditStatus, skippedFiles) {
	const summaryPath = process.env.GITHUB_STEP_SUMMARY;
	if (!summaryPath) return;
	const md = buildStepSummaryMarkdown(workspaceReal, result, auditStatus, skippedFiles);
	(0, node_fs.appendFileSync)(summaryPath, `${md}\n`, "utf8");
}
// dist-ts/pr-comment.js
const PR_COMMENT_MARKER = "<!-- castov-security-audit -->";
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
/**
* Builds a data-minimized PR comment containing ONLY severity counts, rule IDs,
* sanitized relative file paths, and generic static rule explanations.
* Never includes raw or masked evidence, secrets, or environment values.
*/
function buildPrCommentBody(workspaceReal, result, auditStatus, skippedFiles) {
	const lines = [
		PR_COMMENT_MARKER,
		"## Castov Security Audit",
		""
	];
	if (auditStatus === "incomplete") {
		lines.push(`> **Incomplete Coverage**: ${skippedFiles.length} file(s) or directory(ies) were skipped due to scan limits or permissions.`);
		lines.push("");
	}
	lines.push(`**Status**: \`${auditStatus}\` | **Critical**: ${result.counts.critical} | **High**: ${result.counts.high} | **Medium**: ${result.counts.medium} | **Low**: ${result.counts.low} | **Info**: ${result.counts.info}`);
	lines.push("");
	const active = result.findings.filter((f) => !f.isBaselineSuppressed);
	if (active.length === 0 && auditStatus === "complete") lines.push("No security findings detected.");
	else if (active.length > 0) {
		lines.push("| Severity | Rule | File | Description |");
		lines.push("| :--- | :--- | :--- | :--- |");
		for (const f of active.slice(0, 30)) {
			const ruleId = sanitizeMarkdownText(f.ruleId);
			const rel = sanitizeMarkdownText(toWorkspaceRelativePosix(workspaceReal, f.file));
			const genericTitle = sanitizeMarkdownText(ALL_RULES_METADATA[f.ruleId]?.title || `Security rule ${f.ruleId} triggered`);
			lines.push(`| ${f.severity.toUpperCase()} | ${ruleId} | \`${rel}\` | ${genericTitle} |`);
		}
	}
	return lines.join("\n");
}
function resolvePrNumberFromEvent() {
	if (process.env.GITHUB_EVENT_NAME !== "pull_request") return null;
	const eventPath = process.env.GITHUB_EVENT_PATH;
	if (!eventPath) return null;
	try {
		const num = JSON.parse((0, node_fs.readFileSync)(eventPath, "utf8")).pull_request?.number;
		if (typeof num === "number" && Number.isInteger(num) && num > 0) return num;
	} catch {
		return null;
	}
	return null;
}
async function upsertPrComment(opts) {
	const repo = process.env.GITHUB_REPOSITORY || "";
	if (!REPO_RE.test(repo)) return {
		posted: false,
		action: "skipped",
		warning: "Invalid or missing GITHUB_REPOSITORY; skipping PR comment."
	};
	const prNumber = resolvePrNumberFromEvent();
	if (!prNumber) return {
		posted: false,
		action: "skipped",
		warning: "Not a pull_request event with valid PR number; skipping PR comment."
	};
	if (!opts.token) return {
		posted: false,
		action: "skipped",
		warning: "Missing GitHub token; skipping PR comment."
	};
	const apiBase = (opts.apiBaseUrl || process.env.GITHUB_API_URL || "https://api.github.com").replace(/\/+$/, "");
	const headers = {
		Accept: "application/vnd.github+json",
		Authorization: `Bearer ${opts.token}`,
		"Content-Type": "application/json",
		"User-Agent": "castov-action"
	};
	const body = buildPrCommentBody(opts.workspaceReal, opts.result, opts.auditStatus, opts.skippedFiles);
	const listUrl = `${apiBase}/repos/${repo}/issues/${prNumber}/comments?per_page=100`;
	try {
		const listRes = await fetch(listUrl, {
			headers,
			signal: AbortSignal.timeout(1e4)
		});
		if (!listRes.ok) return {
			posted: false,
			action: "skipped",
			warning: `GitHub API comment lookup returned HTTP ${listRes.status}; skipping PR comment.`
		};
		const comments = await listRes.json();
		const existing = Array.isArray(comments) ? comments.find((c) => typeof c.id === "number" && typeof c.body === "string" && c.body.includes("<!-- castov-security-audit -->")) : void 0;
		if (existing?.id) {
			const patchUrl = `${apiBase}/repos/${repo}/issues/comments/${existing.id}`;
			const patchRes = await fetch(patchUrl, {
				method: "PATCH",
				headers,
				body: JSON.stringify({ body }),
				signal: AbortSignal.timeout(1e4)
			});
			if (!patchRes.ok) return {
				posted: false,
				action: "skipped",
				warning: `GitHub API comment update returned HTTP ${patchRes.status}; skipping PR comment.`
			};
			return {
				posted: true,
				action: "updated"
			};
		}
		const postUrl = `${apiBase}/repos/${repo}/issues/${prNumber}/comments`;
		const postRes = await fetch(postUrl, {
			method: "POST",
			headers,
			body: JSON.stringify({ body }),
			signal: AbortSignal.timeout(1e4)
		});
		if (!postRes.ok) return {
			posted: false,
			action: "skipped",
			warning: `GitHub API comment creation returned HTTP ${postRes.status}; skipping PR comment.`
		};
		return {
			posted: true,
			action: "created"
		};
	} catch (err) {
		return {
			posted: false,
			action: "skipped",
			warning: `GitHub API PR comment request failed (${err instanceof Error ? err.message : String(err)}); skipping PR comment.`
		};
	}
}
// dist-ts/main.js
function getInput(name, fallback = "") {
	const key = `INPUT_${name.toUpperCase()}`;
	const val = process.env[key];
	return typeof val === "string" ? val.trim() : fallback;
}
function parseBoolInput(name, defaultValue) {
	const raw = getInput(name);
	if (!raw) return defaultValue;
	return raw.toLowerCase() !== "false";
}
function parseOptionalIntEnv(name) {
	const raw = process.env[name];
	if (!raw) return void 0;
	const n = Number.parseInt(raw, 10);
	return Number.isFinite(n) && n > 0 ? n : void 0;
}
function normalizeFormat(raw) {
	const lower = raw.toLowerCase();
	if (lower === "sarif" || lower === "json" || lower === "md" || lower === "text") return lower;
	throw new Error(`Unsupported report format "${raw}". Expected one of: sarif, json, md, text.`);
}
function normalizeFailOn(raw) {
	const lower = raw.toLowerCase();
	if (lower === "critical" || lower === "high" || lower === "medium" || lower === "low" || lower === "none") return lower;
	throw new Error(`Unsupported fail-on severity "${raw}". Expected one of: critical, high, medium, low, none.`);
}
async function runAction() {
	const workspaceRaw = process.env.GITHUB_WORKSPACE || process.cwd();
	let workspaceReal;
	try {
		workspaceReal = resolveWorkspaceRoot(workspaceRaw);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		process.stderr.write(`Castov Action failed: unable to resolve workspace (${stripControlAndBidi(msg)})\n`);
		writeGitHubOutputs({
			"audit-status": "failed",
			"exit-code": "1"
		});
		return 1;
	}
	try {
		const targetInput = getInput("path", ".") || ".";
		const format = normalizeFormat(getInput("format", "sarif") || "sarif");
		const failOn = normalizeFailOn(getInput("fail-on", "high") || "high");
		const failOnIncomplete = parseBoolInput("fail-on-incomplete", true);
		const baselineInput = getInput("baseline", "");
		const ignoreRaw = getInput("ignore-rules", "");
		const reportFileInput = getInput("report-file", "castov-results.sarif") || "castov-results.sarif";
		const sarifFileInput = getInput("sarif-file", "");
		const annotationsEnabled = parseBoolInput("annotations", true);
		const summaryEnabled = parseBoolInput("summary", true);
		const commentOnPr = parseBoolInput("comment-on-pr", false);
		const githubToken = getInput("github-token", process.env.GITHUB_TOKEN || "");
		const targetReal = resolveContainedExistingPath(workspaceReal, targetInput);
		const baselineResolved = baselineInput ? resolveContainedExistingPath(workspaceReal, baselineInput, { allowMissing: true }) : void 0;
		const reportWritePath = resolveContainedWritePath(workspaceReal, reportFileInput);
		const sarifWritePath = sarifFileInput ? resolveContainedWritePath(workspaceReal, sarifFileInput) : format === "sarif" ? reportWritePath : void 0;
		const { inputFiles, skippedFiles } = discoverActionFiles(workspaceReal, targetReal, {
			maxDepth: parseOptionalIntEnv("CASTOV_MAX_DEPTH"),
			maxFiles: parseOptionalIntEnv("CASTOV_MAX_FILES"),
			maxFileBytes: parseOptionalIntEnv("CASTOV_MAX_FILE_BYTES"),
			maxTotalBytes: parseOptionalIntEnv("CASTOV_MAX_TOTAL_BYTES")
		});
		const baselineState = loadBaselineState(baselineResolved);
		const nowIso = process.env.CASTOV_SCANNED_AT || (/* @__PURE__ */ new Date()).toISOString();
		const { result } = runAuditCore(inputFiles, {
			failOn,
			ignoreRules: ignoreRaw ? ignoreRaw.split(",").map((s) => s.trim()).filter(Boolean) : [],
			toolVersion: "1.0.0",
			scannedAt: nowIso,
			baselineCreatedAt: nowIso
		}, baselineState, {
			fileExists: (p) => {
				try {
					if (!(0, node_fs.existsSync)(p) || (0, node_fs.lstatSync)(p).isSymbolicLink()) return false;
					return isPathInside(workspaceReal, (0, node_fs.realpathSync)(p));
				} catch {
					return false;
				}
			},
			sha256: (s) => (0, node_crypto.createHash)("sha256").update(s, "utf8").digest("hex")
		});
		const writeQueue = [{
			targetPath: reportWritePath,
			content: formatAuditOutput(result, {
				format,
				useColor: false
			})
		}];
		if (sarifWritePath && sarifWritePath !== reportWritePath) writeQueue.push({
			targetPath: sarifWritePath,
			content: formatAuditOutput(result, { format: "sarif" })
		});
		atomicWriteFiles(writeQueue);
		const auditStatus = skippedFiles.length > 0 ? "incomplete" : "complete";
		let finalExitCode = 0;
		if (result.exitCode === 1) finalExitCode = 1;
		else if (auditStatus === "incomplete" && failOnIncomplete) finalExitCode = 1;
		if (annotationsEnabled) emitWorkflowAnnotations(workspaceReal, result.findings);
		if (summaryEnabled) writeStepSummary(workspaceReal, result, auditStatus, skippedFiles);
		if (commentOnPr) {
			if (githubToken && process.env.GITHUB_ACTIONS === "true") {
				const maskedToken = stripControlAndBidi(githubToken).replace(/[\r\n]/g, "");
				if (maskedToken) process.stdout.write(`::add-mask::${maskedToken}\n`);
			}
			const commentRes = await upsertPrComment({
				workspaceReal,
				result,
				auditStatus,
				skippedFiles,
				token: githubToken
			});
			if (commentRes.warning) process.stdout.write(`::warning::${stripControlAndBidi(commentRes.warning)}\n`);
		}
		const reportRel = toWorkspaceRelativePosix(workspaceReal, reportWritePath);
		const sarifRel = sarifWritePath ? toWorkspaceRelativePosix(workspaceReal, sarifWritePath) : "";
		writeGitHubOutputs({
			"audit-status": auditStatus,
			"exit-code": String(finalExitCode),
			"findings-count": String(result.findings.length),
			"critical-count": String(result.counts.critical),
			"high-count": String(result.counts.high),
			"skipped-files-count": String(skippedFiles.length),
			"report-file": reportRel,
			"sarif-file": sarifRel
		});
		return finalExitCode;
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		process.stderr.write(`Castov Action failed: ${stripControlAndBidi(msg)}\n`);
		writeGitHubOutputs({
			"audit-status": "failed",
			"exit-code": "1"
		});
		return 1;
	}
}
runAction().then((exitCode) => {
	process.exitCode = exitCode;
});
exports.runAction = runAction;
