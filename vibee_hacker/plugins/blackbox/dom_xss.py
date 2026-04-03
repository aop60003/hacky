"""DOM-based XSS and Prototype Pollution detection."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Result, Severity, Target

# DOM XSS source patterns (user-controllable input)
DOM_SOURCES = [
    r"document\.location", r"document\.URL", r"document\.referrer",
    r"document\.cookie", r"window\.location", r"window\.name",
    r"location\.hash", r"location\.search", r"location\.href",
    r"document\.documentURI", r"document\.baseURI",
]

# DOM XSS sink patterns (dangerous operations)
DOM_SINKS = [
    r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(",
    r"document\.writeln\s*\(", r"eval\s*\(", r"setTimeout\s*\(",
    r"setInterval\s*\(", r"Function\s*\(", r"\.insertAdjacentHTML\s*\(",
    r"\.src\s*=", r"\.href\s*=", r"jQuery\s*\(\s*['\"]<",
    r"\$\s*\(\s*['\"]<", r"\.html\s*\(",
]

# Prototype Pollution patterns
PROTO_PATTERNS = [
    r"__proto__", r"constructor\.prototype",
    r"Object\.assign\s*\(\s*\{\}", r"merge\s*\(",
    r"extend\s*\(", r"deepCopy\s*\(", r"deepMerge\s*\(",
    r"\[key\]\s*=\s*value", r"obj\[.*\]\s*=",
]

# Dangerous postMessage patterns
POSTMESSAGE_PATTERNS = [
    r"addEventListener\s*\(\s*['\"]message['\"]",
    r"\.onmessage\s*=",
]


class DomXssPlugin(PluginBase):
    name = "dom_xss"
    description = "DOM-based XSS and Prototype Pollution detection via JavaScript analysis"
    category = "blackbox"
    phase = 2
    destructive_level = 0

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        base_url = target.url.rstrip("/")

        async with httpx.AsyncClient(
            verify=getattr(target, "verify_ssl", True),
            timeout=10,
            follow_redirects=True,
        ) as client:
            # 1. Fetch main page
            try:
                resp = await client.get(base_url)
                page_content = resp.text
            except (httpx.TransportError, httpx.InvalidURL):
                return []

            # Analyze inline scripts
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', page_content, re.DOTALL | re.IGNORECASE)
            all_js = "\n".join(inline_scripts)

            # 2. Fetch linked JS files (same domain only)
            js_links = re.findall(r'<script[^>]+src=["\']([^"\']+)', page_content, re.IGNORECASE)
            for js_link in js_links[:10]:
                if js_link.startswith("//"):
                    js_link = "https:" + js_link
                elif js_link.startswith("/"):
                    js_link = base_url + js_link
                elif not js_link.startswith("http"):
                    js_link = base_url + "/" + js_link

                # Same domain only
                if urlparse(js_link).netloc != urlparse(base_url).netloc:
                    continue

                try:
                    js_resp = await client.get(js_link)
                    all_js += "\n" + js_resp.text
                except Exception:
                    continue

            # 3. Check for DOM XSS source→sink patterns
            found_sources = [p for p in DOM_SOURCES if re.search(p, all_js)]
            found_sinks = [p for p in DOM_SINKS if re.search(p, all_js)]

            if found_sources and found_sinks:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.HIGH,
                    title="DOM-based XSS: source-to-sink pattern detected",
                    description=(
                        f"JavaScript contains both DOM XSS sources ({len(found_sources)}) "
                        f"and sinks ({len(found_sinks)}). "
                        f"Sources: {', '.join(s.replace(chr(92), '') for s in found_sources[:3])}. "
                        f"Sinks: {', '.join(s.replace(chr(92), '') for s in found_sinks[:3])}."
                    ),
                    endpoint=base_url,
                    rule_id="dom_xss_source_sink",
                    cwe_id="CWE-79",
                    recommendation="Sanitize all DOM sources before passing to sinks. Use textContent instead of innerHTML.",
                ))
            elif found_sinks:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.MEDIUM,
                    title="Potential DOM XSS: dangerous sinks found",
                    description=f"JavaScript uses {len(found_sinks)} dangerous DOM sinks without clear source validation.",
                    endpoint=base_url,
                    rule_id="dom_xss_dangerous_sinks",
                    cwe_id="CWE-79",
                    recommendation="Review JavaScript for proper input sanitization before DOM manipulation.",
                ))

            # 4. Check for Prototype Pollution
            for pattern in PROTO_PATTERNS:
                if re.search(pattern, all_js):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="Prototype Pollution risk detected",
                        description=f"JavaScript contains prototype pollution pattern: {pattern}",
                        endpoint=base_url,
                        rule_id="dom_prototype_pollution",
                        cwe_id="CWE-1321",
                        recommendation="Freeze prototypes. Validate object keys. Use Map instead of plain objects.",
                    ))
                    break  # One finding is enough

            # 5. Check for unsafe postMessage
            for pattern in POSTMESSAGE_PATTERNS:
                if re.search(pattern, all_js):
                    # Check if origin is validated
                    if not re.search(r'origin\s*[!=]==', all_js):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.MEDIUM,
                            title="Unsafe postMessage handler (no origin check)",
                            description="postMessage event listener found without origin validation.",
                            endpoint=base_url,
                            rule_id="dom_postmessage_no_origin",
                            cwe_id="CWE-346",
                            recommendation="Always validate event.origin in postMessage handlers.",
                        ))
                    break

        return results[:10]
