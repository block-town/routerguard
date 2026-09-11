// guard-plugin.js: opencode `tool.execute.before` hook. Same rule shape as the router-side
// gate, enforced inside the harness before a tool runs. Covers sessions the router never
// sees (a provider configured directly) and unattended runs where "ask" is auto-rejected.
//
// Install: copy to ~/.config/opencode/plugins/guard-plugin.js (opencode loads every plugin
// in that directory). Rules: ~/.config/opencode/guard-rules.json, generated with
//   python adapters/opencode/rules_to_json.py rules.yaml > ~/.config/opencode/guard-rules.json
// or OPENCODE_GUARD_RULES=/path/to/guard-rules.json. Without a file the built-in defaults below apply.
// Log: ~/.local/share/opencode/guard.log (JSON lines), or OPENCODE_GUARD_LOG.
//
// A `block` throws, which opencode reports to the model as a failed tool call; the agent
// loop continues. A `flag` only logs. Patterns are tested case-insensitive and multiline
// against the tool name plus every string value in the (decoded) arguments.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const RULES_PATH =
  process.env.OPENCODE_GUARD_RULES || path.join(os.homedir(), ".config", "opencode", "guard-rules.json");
const LOG_PATH =
  process.env.OPENCODE_GUARD_LOG || path.join(os.homedir(), ".local", "share", "opencode", "guard.log");

// Mirrors rules.example.yaml. Keep in sync or generate guard-rules.json from it.
const DEFAULT_RULES = [
  { id: "secret-file", action: "block",
    pattern: String.raw`(^|[\s"'=:(/])(\.env(\.(local|production|prod|dev|development|staging|secret|secrets|keys?))?|\.envrc|\.netrc|\.npmrc|\.pypirc|\.git-credentials)(?=$|[\s"'):;&|>])` },
  { id: "secret-dir", action: "block",
    pattern: String.raw`(~|/Users/[^/\s]+|/home/[^/\s]+|\$HOME)/(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config/gh|\.config/gcloud|\.local/share/opencode/auth\.json)` },
  { id: "secret-dir-relative", action: "block", pattern: String.raw`(^|[\s"'=:(])\.(ssh|aws|gnupg|kube)/` },
  { id: "key-files", action: "block",
    pattern: String.raw`\b(id_rsa|id_ed25519|id_ecdsa|\w*tokens?\.json|credentials\.json|service[-_]account\w*\.json|\.pem|\.p12|\.pfx)\b` },
  { id: "keychain", action: "block", pattern: String.raw`\bsecurity\s+(find-(generic|internet)-password|dump-keychain|export)\b` },
  { id: "redacted-placeholder-exfil", action: "block", pattern: String.raw`<<REDACTED:` },
  { id: "dotfile-glob", action: "block",
    pattern: String.raw`(^|[\s"'=(/])\.[a-z?]{0,2}\?[a-z]\b|(^|[\s"'=(/])\.[a-z]{0,2}(\[[a-z]+\]|\{[a-z,]+\}|["'][a-z]+["'])[a-z]*|(^|[\s"'=(/])\.[a-z]{1,2}\*(?=$|[\s"';&|)])|\*\.(env|envrc|netrc|npmrc|pypirc)\b|(^|[\s"'=:(/])\.env[?*\[]` },
  { id: "find-exec", action: "block",
    pattern: String.raw`\bfind\b[^|\n]*\s-(exec|execdir|ok|okdir)\s+(sudo\s+)?(sh|bash|zsh|dash|python\d*|perl|ruby|node|php|env|xargs|rm|chmod|curl|wget)\b` },
  { id: "rg-pre", action: "block", pattern: String.raw`\brg\b[^|\n]*\s--pre\b` },
  { id: "git-no-index", action: "block", pattern: String.raw`\bgit\s+diff\b[^|\n]*--no-index` },
  { id: "pipe-to-shell", action: "block", pattern: String.raw`\|\s*(sudo\s+)?(ba|z|da|k)?sh\b(\s|$|-)` },
  { id: "pipe-to-interpreter", action: "block",
    pattern: String.raw`\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(python\d*|perl|ruby|node|php)(\s+-)?\s*(;|&|\||$)` },
  { id: "fetch-exec", action: "block",
    pattern: String.raw`\b((ba|z|da|k)?sh|source)\s+(-[a-z]+\s+)*<\(\s*(curl|wget)\b|(^|[\s;&|(])\.\s+<\(\s*(curl|wget)\b|\b((ba|z|da|k)?sh|eval|source|python\d*|perl|ruby|node|php)\b[^|\n]*\$\(\s*(curl|wget)\b` },
  { id: "base64-decode", action: "block", pattern: String.raw`\bbase64\s+(-d|-D|--decode)\b` },
  { id: "reverse-shell", action: "block",
    pattern: String.raw`/dev/tcp/|\|\s*(nc|ncat|netcat)\b|\b(nc|ncat|netcat)\b[^|\n]*\s-e\s*/|\bsocat\b[^|\n]*\b(exec|tcp)|\bmkfifo\b[^|\n]*\b(nc|ncat)\b` },
  { id: "env-to-network", action: "block", pattern: String.raw`\b(env|printenv)\b[^|\n]*\|\s*(curl|wget|nc|ncat)\b` },
  { id: "shell-rc-write", action: "block",
    pattern: String.raw`>{1,2}\s*["']?[^\s"']*\.(zshrc|zshenv|zprofile|bashrc|bash_profile|profile)\b` },
  { id: "sudo", action: "block", pattern: String.raw`(^|[\s;&|(])sudo\s` },
  { id: "upload", action: "flag", pattern: String.raw`\b(curl|wget)\b[^\n]*\s(-d|--data\S*|-F|--form|-T|--upload-file)\s` },
  { id: "package-install", action: "flag",
    pattern: String.raw`\b(pip3?|uv)\s+(install|add)\b|\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b|\bbrew\s+install\b` },
  { id: "launchd-cron", action: "flag", pattern: String.raw`\blaunchctl\s+(load|bootstrap|submit|kickstart)\b|\bcrontab\b` },
  { id: "eval-or-obfuscation", action: "flag", pattern: String.raw`\beval\b|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|\$'\\x` },
  { id: "osascript", action: "flag", pattern: String.raw`\bosascript\b` },
  { id: "transform-pipe", action: "flag", pattern: String.raw`\|\s+(base64|rev|od|xxd|hexdump|gzip|xz|bzip2|zstd|zip|openssl|gpg)\b` },
  { id: "fetch-then-run", action: "block",
    pattern: String.raw`\b(curl|wget)\b[^\n]*\s(-o|--output)\s*["']?([^\s"']+)["']?[^\n]*(;|&&)\s*(\b((ba|z|da|k)?sh|python\d*|node|perl|ruby|php|source)\s+["']?|\bchmod\s+\+x\s+["']?|\./|)\3(?=$|[\s"';&|)])` },
];

function compile(rules) {
  const out = [];
  for (const r of rules) {
    if (!r || typeof r.pattern !== "string" || r.pattern.startsWith("__")) continue;
    try {
      out.push({ id: r.id, action: r.action === "block" ? "block" : "flag", rx: new RegExp(r.pattern, "im") });
    } catch (e) {
      log({ event: "bad-rule", id: r.id, error: String(e) });
    }
  }
  return out;
}

function loadRules() {
  try {
    const parsed = JSON.parse(fs.readFileSync(RULES_PATH, "utf8"));
    const rules = compile(parsed.rules || []);
    if (rules.length) return { rules, source: RULES_PATH };
  } catch (_) {
    /* fall through to defaults */
  }
  return { rules: compile(DEFAULT_RULES), source: "builtin" };
}

function strings(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => strings(v, out));
  else if (value && typeof value === "object") Object.values(value).forEach((v) => strings(v, out));
  return out;
}

function log(entry) {
  try {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    fs.appendFileSync(LOG_PATH, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
  } catch (_) {
    /* logging must never break a tool call */
  }
}

export const GuardPlugin = async () => {
  let state = loadRules();
  let loadedAt = Date.now();
  return {
    "tool.execute.before": async (input, output) => {
      if (Date.now() - loadedAt > 30_000) {
        state = loadRules();
        loadedAt = Date.now();
      }
      const texts = strings(output?.args);
      const hay = [input?.tool || "", ...texts].join("\n");
      const digest = crypto.createHash("sha256").update(hay).digest("hex");
      for (const r of state.rules) {
        if (!r.rx.test(hay)) continue;
        log({ event: r.action, rule: r.id, tool: input?.tool, sessionID: input?.sessionID, callID: input?.callID,
              sha256: digest, prefix: texts.join(" ").slice(0, 200) });
        if (r.action === "block") {
          throw new Error(
            `[guard] Blocked tool call ${input?.tool} (rule: ${r.id}). ` +
              `This action is not permitted by policy; do not retry it, continue with the task.`
          );
        }
      }
    },
  };
};
