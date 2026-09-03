#!/usr/bin/env python3
"""
Cloudflare Bypass Engine

Multi-layered automated challenge solver and evidence collector.
Supports CloudScraper, Playwright Stealth, Archive fallbacks, and Header Mutations.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from curl_cffi import requests

UA_POOL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
]

CRAWLER_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "curl/8.4.0",
]

BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

CF_INDICATORS = [
    "cloudflare", "cf-ray", "cf-cache-status", "__cfduid", "cf-request-id",
    "arkose", "jschl_vc", "jschl_answer", "attention required",
    "please wait", "checking your browser", "verify you are human",
    "challenge-platform",
]


@dataclass
class Evidence:
    technique: str
    url: str
    status_code: int = 0
    final_url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    bypassed: bool = False
    challenge_detected: bool = False
    notes: str = ""
    error: str = ""
    html_path: str = ""
    screenshot_path: str = ""


@dataclass
class BypassReport:
    target: str
    waf: str = "unknown"
    cloudflare_detected: bool = False
    final_url: str = ""
    cookies_json_path: str = ""
    curl_command: str = ""
    html_content: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    techniques_used: List[str] = field(default_factory=list)
    results: List[Evidence] = field(default_factory=list)

    def summary_count(self) -> Dict[str, int]:
        return {
            "total": len(self.results),
            "bypassed": sum(1 for r in self.results if r.bypassed),
            "challenges": sum(1 for r in self.results if r.challenge_detected),
        }


class WAFDetector:
    @staticmethod
    def normalize_target(target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        parsed = urlparse(target)
        return parsed.netloc or parsed.path

    @staticmethod
    def is_challenge(resp: requests.Response) -> bool:
        text = (resp.text or "").lower()
        server = (resp.headers.get("Server", "") or "").lower()
        if "cloudflare" in server:
            return True
        for k in ["cf-ray", "cf-cache-status", "__cfduid", "cf_clearance", "cf-request-id"]:
            if k in resp.headers:
                return True
        for phrase in CF_INDICATORS:
            if phrase in text:
                return True
        if resp.status_code in (403, 429, 503):
            return True
        return False

    @classmethod
    def fingerprint(cls, domain: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"waf": "unknown", "cloudflare": False, "challenge_detected": False}
        try:
            s = requests.Session()
            headers = dict(BASE_HEADERS)
            headers["User-Agent"] = random.choice(UA_POOL)
            r = s.get(f"https://{domain}", headers=headers, timeout=12, allow_redirects=True, verify=False)
            server = r.headers.get("Server", "").lower()
            if "cloudflare" in server:
                info["waf"] = "cloudflare"
                info["cloudflare"] = True
            elif "incapsula" in server:
                info["waf"] = "incapsula"
            elif "distil" in server:
                info["waf"] = "distil"
            info["challenge_detected"] = cls.is_challenge(r)
        except Exception as e:
            info["error"] = str(e)
        return info


class CloudScraperSolver:
    @staticmethod
    def solve(domain: str, output_dir: Path) -> Evidence:
        evidence = Evidence(technique="cloudscraper", url=f"https://{domain}")
        try:
            import cloudscraper
            s = cloudscraper.create_scraper(
                browser={"browser": "chrome", "platform": "darwin", "mobile": False}
            )
            r = s.get(f"https://{domain}", timeout=20)
            evidence.status_code = r.status_code
            evidence.final_url = str(r.url)
            evidence.headers = dict(r.headers)
            evidence.body_preview = r.text[:1500] if r.text else ""
            evidence.cookies = {c.name: c.value for c in r.cookies}
            evidence.challenge_detected = WAFDetector.is_challenge(r)
            evidence.bypassed = (
                200 <= r.status_code < 400 and not evidence.challenge_detected
            )
            if evidence.bypassed:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                html_path = output_dir / f"cf_bypass_{domain.replace('.','_')}_{stamp}.html"
                html_path.write_text(r.text, encoding="utf-8", errors="ignore")
                evidence.html_path = str(html_path)
        except Exception as e:
            evidence.error = str(e)
            evidence.challenge_detected = True
        return evidence


class PlaywrightStealthSolver:
    @staticmethod
    def solve(domain: str, output_dir: Path) -> Evidence:
        evidence = Evidence(technique="playwright-stealth", url=f"https://{domain}")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            evidence.error = "playwright package not installed"
            return evidence

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        html_path = output_dir / f"cf_bypass_{domain.replace('.','_')}_{stamp}.html"
        screenshot_path = output_dir / f"cf_bypass_{domain.replace('.','_')}_{stamp}.png"

        try:
            ua = random.choice(UA_POOL)
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                    ],
                )
                context = browser.new_context(
                    user_agent=ua,
                    viewport={"width": 1920, "height": 1080},
                    locale="en-US",
                    timezone_id="America/New_York",
                    ignore_https_errors=True,
                )
                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    delete navigator.__proto__.webdriver;
                    window.chrome = { runtime: {} };
                    Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                    Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
                """)
                page = context.new_page()
                r = page.goto(f"https://{domain}", wait_until="domcontentloaded", timeout=30000)
                time.sleep(3)

                content = page.content()
                evidence.status_code = r.status if r else 0
                evidence.final_url = page.url
                evidence.body_preview = content[:1500] if content else ""
                evidence.cookies = {c["name"]: c["value"] for c in context.cookies()}
                evidence.headers = {k: v for k, v in r.headers.items()} if r else {}

                content_lower = (content or "").lower()
                evidence.challenge_detected = (
                    any(p in content_lower for p in CF_INDICATORS)
                    or "cloudflare" in (evidence.headers.get("Server", "")).lower()
                )
                evidence.bypassed = (
                    evidence.status_code in (200, 301, 302)
                    and not evidence.challenge_detected
                )

                if evidence.bypassed or evidence.status_code == 200:
                    html_path.write_text(content or "", encoding="utf-8", errors="ignore")
                    evidence.html_path = str(html_path)
                    try:
                        page.screenshot(path=str(screenshot_path), full_page=False)
                        evidence.screenshot_path = str(screenshot_path)
                    except Exception:
                        pass
                browser.close()
        except Exception as e:
            evidence.error = str(e)
            evidence.challenge_detected = True
        return evidence


class ArchiveFallbackSolver:
    @staticmethod
    def solve(domain: str, output_dir: Path) -> List[Evidence]:
        results: List[Evidence] = []
        urls = [
            f"https://web.archive.org/web/{domain}",
            f"https://archive.today/{domain}",
        ]
        for url in urls:
            try:
                s = requests.Session()
                headers = dict(BASE_HEADERS)
                headers["User-Agent"] = random.choice(UA_POOL)
                r = s.get(url, headers=headers, timeout=15, verify=False)
                ev = Evidence(
                    technique="archive",
                    url=url,
                    status_code=r.status_code,
                    final_url=str(r.url),
                    bypassed=200 <= r.status_code < 400,
                )
                if r.text:
                    ev.body_preview = r.text[:1500]
                results.append(ev)
            except Exception as e:
                results.append(Evidence(technique="archive", url=url, error=str(e)))
        return results


class HeaderMutationSolver:
    @staticmethod
    def solve(domain: str) -> List[Evidence]:
        results: List[Evidence] = []
        base = f"https://{domain}"
        for ua in CRAWLER_UAS[:4]:
            try:
                s = requests.Session()
                headers = dict(BASE_HEADERS)
                headers["User-Agent"] = ua
                r = s.get(base, headers=headers, timeout=10, verify=False)
                ev = Evidence(
                    technique="crawler-ua",
                    url=base,
                    status_code=r.status_code,
                    bypassed=200 <= r.status_code < 400 and not WAFDetector.is_challenge(r),
                    challenge_detected=WAFDetector.is_challenge(r),
                    notes=f"UA={ua[:50]}",
                )
                results.append(ev)
            except Exception as e:
                results.append(Evidence(technique="crawler-ua", url=base, error=str(e)))
        return results


class Engine:
    def __init__(self, target: str, output_dir: Optional[Path] = None):
        self.domain = WAFDetector.normalize_target(target)
        self.output_dir = output_dir or (Path.cwd() / "output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> BypassReport:
        fp = WAFDetector.fingerprint(self.domain)
        print(f"Target: {self.domain} | WAF: {fp.get('waf')} | Challenge: {fp.get('challenge_detected')}")

        results: List[Evidence] = []
        best: Optional[Evidence] = None

        # 1. CloudScraper
        print("Running CloudScraper...")
        cs_ev = CloudScraperSolver.solve(self.domain, self.output_dir)
        results.append(cs_ev)
        if cs_ev.bypassed:
            best = cs_ev

        # 2. Playwright Stealth
        if not best or not best.bypassed:
            print("Running Playwright Stealth...")
            pw_ev = PlaywrightStealthSolver.solve(self.domain, self.output_dir)
            results.append(pw_ev)
            if pw_ev.bypassed:
                best = pw_ev

        # 3. Archives Fallback
        if not best or not best.bypassed:
            print("Checking Archive Fallbacks...")
            results.extend(ArchiveFallbackSolver.solve(self.domain, self.output_dir))

        # 4. Crawler UAs
        if not best or not best.bypassed:
            print("Testing Crawler UA Mutations...")
            results.extend(HeaderMutationSolver.solve(self.domain))

        cookies = best.cookies if best and best.bypassed else {}
        curl_cmd = self._build_curl(self.domain, cookies) if cookies else ""

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        cookies_json_path = ""
        if cookies:
            cookies_json_path = str(self.output_dir / f"cf_cookies_{self.domain.replace('.','_')}_{stamp}.json")
            Path(cookies_json_path).write_text(json.dumps(cookies, indent=2))

        report = BypassReport(
            target=self.domain,
            waf=fp.get("waf", "unknown"),
            cloudflare_detected=fp.get("cloudflare", False),
            final_url=best.final_url if best else "",
            cookies_json_path=cookies_json_path,
            curl_command=curl_cmd,
            html_content=best.body_preview if best else "",
            results=results,
        )

        out_json = self.output_dir / f"cf_bypass_{self.domain.replace('.','_')}_{stamp}.json"
        out_json.write_text(json.dumps(asdict(report), indent=2, default=str))
        print(f"Report saved to {out_json}")
        return report

    @staticmethod
    def _build_curl(domain: str, cookies: Dict[str, str]) -> str:
        parts = ["curl", "-k", "-L", f"https://{domain}"]
        for k, v in cookies.items():
            parts += ["-b", f"{k}={v}"]
        return " ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Cloudflare Bypass Engine")
    parser.add_argument("target", help="Target domain or URL (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Output directory for reports")
    args = parser.parse_args()

    out_dir = Path(args.output) if args.output else None
    engine = Engine(args.target, out_dir)
    engine.run()


if __name__ == "__main__":
    main()
