"""Shared helpers: env-file parsing, upstream labelling, redaction. No values ever leave here."""
import os
import re

MIN_SECRET_LEN = 12

# Hosts that are the model maker's own API. Everything else that serves a model is an
# intermediary (a router or reseller re-packaging someone else's model). Extend with
# --first-party on the command line.
FIRST_PARTY_HOSTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "api.deepseek.com",
    "api.mistral.ai",
    "api.cohere.com",
    "api.x.ai",
    "api.moonshot.ai",
    "api.z.ai",
    "open.bigmodel.cn",
    "dashscope.aliyuncs.com",
    "integrate.api.nvidia.com",
    "api.groq.com",
    "api.cerebras.ai",
    "api.sambanova.ai",
    "bedrock-runtime",
    "openai.azure.com",
)


def strip_quotes(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def load_env_file(path, secrets, key_names_loaded):
    """Parse KEY=value lines, adding qualifying values into `secrets` (value -> key name,
    first name wins) and each accepted key name to key_names_loaded. Returns False if unreadable."""
    try:
        with open(os.path.expanduser(path), "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return False
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = strip_quotes(value)
        if len(value) < MIN_SECRET_LEN or value.lower().startswith(("http://", "https://")):
            continue
        key_names_loaded.append(key)
        secrets.setdefault(value, key)
    return True


def compile_pattern(secrets):
    values = sorted(secrets, key=len, reverse=True)
    return re.compile("|".join(re.escape(v) for v in values)) if values else None


def redact(pattern, secrets, text):
    """Replace every secret value in text with <KEY_NAME>. Call BEFORE truncating."""
    if not text or pattern is None:
        return text or ""
    return pattern.sub(lambda m: f"<{secrets[m.group(0)]}>", text)


def host_of(api_base):
    if not api_base:
        return ""
    s = api_base.lower()
    s = re.sub(r"^[a-z]+://", "", s)
    return s.split("/", 1)[0]


def label_upstream(api_base, extra_first_party=()):
    """'first-party (host)' or 'intermediary (host)' or 'unknown'."""
    host = host_of(api_base)
    if not host:
        return "unknown"
    for needle in tuple(FIRST_PARTY_HOSTS) + tuple(extra_first_party):
        if needle and needle.lower() in host:
            return f"first-party ({host})"
    return f"intermediary ({host})"


def is_intermediary(label):
    return label.startswith("intermediary")
