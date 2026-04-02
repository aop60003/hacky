"""Browser automation tool using Playwright.

Provides headless browser control for the agent:
- Navigate to URLs, click elements, fill forms
- Execute JavaScript (DOM XSS detection, token extraction)
- Multi-tab management
- Console log capture
- Page source extraction
- Screenshot/PDF capture
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Singleton browser manager
_browser_mgr: Optional["BrowserManager"] = None

MAX_SOURCE_LENGTH = 30_000
MAX_CONSOLE_LOGS = 200


class BrowserManager:
    """Manages a Playwright browser instance with multiple tabs."""

    def __init__(self):
        self._playwright = None
        self._browser = None
        self._contexts: Dict[str, Any] = {}  # tab_id -> (context, page)
        self._active_tab: Optional[str] = None
        self._tab_counter = 0
        self._console_logs: Dict[str, List[str]] = {}

    async def _ensure_browser(self) -> None:
        if self._browser:
            return
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise RuntimeError("playwright not installed. Run: pip install playwright && playwright install chromium")

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=["--disable-web-security", "--no-sandbox"],
        )

    async def new_tab(self, url: Optional[str] = None) -> str:
        await self._ensure_browser()
        self._tab_counter += 1
        tab_id = f"tab_{self._tab_counter}"

        context = await self._browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        page = await context.new_page()
        self._console_logs[tab_id] = []

        page.on("console", lambda msg, tid=tab_id: self._on_console(tid, msg))

        if url:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

        self._contexts[tab_id] = (context, page)
        self._active_tab = tab_id
        return tab_id

    def _on_console(self, tab_id: str, msg: Any) -> None:
        logs = self._console_logs.get(tab_id, [])
        if len(logs) < MAX_CONSOLE_LOGS:
            logs.append(f"[{msg.type}] {msg.text}")

    def _get_page(self, tab_id: Optional[str] = None) -> Any:
        tid = tab_id or self._active_tab
        if not tid or tid not in self._contexts:
            raise ValueError(f"No such tab: {tid}. Use browser_new_tab first.")
        return self._contexts[tid][1]

    async def close_tab(self, tab_id: str) -> None:
        if tab_id in self._contexts:
            ctx, page = self._contexts.pop(tab_id)
            await page.close()
            await ctx.close()
            self._console_logs.pop(tab_id, None)
            if self._active_tab == tab_id:
                self._active_tab = next(iter(self._contexts), None)

    async def close_all(self) -> None:
        for tid in list(self._contexts):
            await self.close_tab(tid)
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None


def _get_mgr() -> BrowserManager:
    global _browser_mgr
    if _browser_mgr is None:
        _browser_mgr = BrowserManager()
    return _browser_mgr


@register_tool(description="Open a new browser tab, optionally navigating to a URL.")
async def browser_new_tab(url: Optional[str] = None) -> Dict[str, Any]:
    """Open a new browser tab. Returns tab_id."""
    try:
        mgr = _get_mgr()
        tab_id = await mgr.new_tab(url)
        page = mgr._get_page(tab_id)
        return {"tab_id": tab_id, "url": page.url, "title": await page.title()}
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="Navigate the browser to a URL.")
async def browser_goto(url: str, tab_id: Optional[str] = None) -> Dict[str, Any]:
    """Navigate to a URL in the active or specified tab."""
    try:
        page = _get_mgr()._get_page(tab_id)
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        status = resp.status if resp else None
        return {"url": page.url, "title": await page.title(), "status": status}
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="Click an element by CSS selector.")
async def browser_click(selector: str, tab_id: Optional[str] = None) -> Dict[str, Any]:
    """Click an element matching the CSS selector."""
    try:
        page = _get_mgr()._get_page(tab_id)
        await page.click(selector, timeout=10000)
        await page.wait_for_load_state("domcontentloaded", timeout=5000)
        return {"clicked": selector, "url": page.url}
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="Type text into an input element by CSS selector.")
async def browser_type(
    selector: str, text: str, tab_id: Optional[str] = None
) -> Dict[str, Any]:
    """Type text into an input field."""
    try:
        page = _get_mgr()._get_page(tab_id)
        await page.fill(selector, text, timeout=10000)
        return {"typed": text[:50], "selector": selector}
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="Execute JavaScript code in the browser and return the result.")
async def browser_execute_js(
    js_code: str, tab_id: Optional[str] = None
) -> Dict[str, Any]:
    """Execute JavaScript in the page context. Returns the evaluation result."""
    try:
        page = _get_mgr()._get_page(tab_id)
        result = await page.evaluate(js_code)
        return {"result": str(result)[:10000]}
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="Get the page HTML source (truncated to 30K chars).")
async def browser_view_source(tab_id: Optional[str] = None) -> Dict[str, Any]:
    """Get the current page source."""
    try:
        page = _get_mgr()._get_page(tab_id)
        content = await page.content()
        return {
            "source": content[:MAX_SOURCE_LENGTH],
            "length": len(content),
            "url": page.url,
        }
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="Get captured browser console logs (console.log, errors, warnings).")
async def browser_get_console_logs(tab_id: Optional[str] = None) -> Dict[str, Any]:
    """Get console log messages captured from the page."""
    mgr = _get_mgr()
    tid = tab_id or mgr._active_tab
    logs = mgr._console_logs.get(tid, [])
    return {"logs": logs, "count": len(logs), "tab_id": tid}


@register_tool(description="Scroll the page down by a number of pixels.")
async def browser_scroll(
    direction: str = "down",
    pixels: int = 500,
    tab_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Scroll the page. Direction: 'down' or 'up'."""
    try:
        page = _get_mgr()._get_page(tab_id)
        delta = pixels if direction == "down" else -pixels
        await page.evaluate(f"window.scrollBy(0, {delta})")
        scroll_y = await page.evaluate("window.scrollY")
        return {"scrolled": direction, "pixels": pixels, "scroll_y": scroll_y}
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="List all open browser tabs.")
async def browser_list_tabs() -> Dict[str, Any]:
    """List all open tabs with their URLs and titles."""
    mgr = _get_mgr()
    tabs = []
    for tid, (ctx, page) in mgr._contexts.items():
        try:
            tabs.append({
                "tab_id": tid,
                "url": page.url,
                "title": await page.title(),
                "active": tid == mgr._active_tab,
            })
        except Exception:
            tabs.append({"tab_id": tid, "error": "page closed"})
    return {"tabs": tabs, "count": len(tabs)}


@register_tool(description="Switch to a different browser tab.")
async def browser_switch_tab(tab_id: str) -> Dict[str, Any]:
    """Switch the active tab."""
    mgr = _get_mgr()
    if tab_id not in mgr._contexts:
        return {"error": f"Tab {tab_id} not found"}
    mgr._active_tab = tab_id
    page = mgr._get_page(tab_id)
    return {"active_tab": tab_id, "url": page.url}


@register_tool(description="Close a browser tab.")
async def browser_close_tab(tab_id: Optional[str] = None) -> Dict[str, Any]:
    """Close the specified or active tab."""
    mgr = _get_mgr()
    tid = tab_id or mgr._active_tab
    if not tid:
        return {"error": "No tab to close"}
    await mgr.close_tab(tid)
    return {"closed": tid, "remaining_tabs": len(mgr._contexts)}


@register_tool(description="Press a keyboard key (Enter, Tab, Escape, etc.).")
async def browser_press_key(
    key: str, tab_id: Optional[str] = None
) -> Dict[str, Any]:
    """Press a keyboard key in the active page."""
    try:
        page = _get_mgr()._get_page(tab_id)
        await page.keyboard.press(key)
        return {"pressed": key}
    except Exception as e:
        return {"error": str(e)}


@register_tool(description="Wait for a specific time or element to appear.")
async def browser_wait(
    milliseconds: int = 1000,
    selector: Optional[str] = None,
    tab_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Wait for time or element. If selector provided, waits for element."""
    try:
        page = _get_mgr()._get_page(tab_id)
        if selector:
            await page.wait_for_selector(selector, timeout=milliseconds)
            return {"waited_for": selector, "found": True}
        else:
            await asyncio.sleep(milliseconds / 1000)
            return {"waited_ms": milliseconds}
    except Exception as e:
        return {"error": str(e)}
