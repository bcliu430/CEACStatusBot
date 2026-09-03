import asyncio
import time

from bs4 import BeautifulSoup
from curl_cffi import requests

from CEACStatusBot.captcha import CaptchaHandle, OnnxCaptchaHandle

CF_INDICATORS = [
    "cloudflare", "just a moment", "checking your browser",
    "challenge-platform", "attention required", "verify you are human",
]

IMPERSONATE_PROFILES = ["chrome", "chrome110", "edge101", "safari15_5"]


def _is_cf_challenge(resp):
    if resp.status_code not in (403, 429, 503):
        return False
    text = (resp.text or "").lower()
    return any(indicator in text for indicator in CF_INDICATORS)


async def _solve_cf_with_nodriver(url):
    """Use nodriver (undetectable Chrome) to solve Cloudflare Turnstile.
    Returns (cookies_dict, page_html, user_agent) or (None, None, None).
    """
    import nodriver as uc

    browser = await uc.start(headless=False)
    try:
        page = await browser.get(url)

        for _ in range(30):
            await asyncio.sleep(2)
            title = await page.evaluate("document.title")
            cookies = await browser.cookies.get_all()
            has_clearance = any(c.name == "cf_clearance" for c in cookies)

            if has_clearance or ("just a moment" not in title.lower() and title):
                await asyncio.sleep(2)
                cookie_dict = {c.name: c.value for c in cookies}
                html = await page.get_content()
                ua = await page.evaluate("navigator.userAgent")
                print(f"nodriver solved CF in {_ * 2}s, got {len(cookie_dict)} cookies")
                return cookie_dict, html, ua

        print("nodriver timed out waiting for CF resolution")
        return None, None, None
    finally:
        browser.stop()


def _solve_cf_nodriver_sync(url):
    """Sync wrapper for the async nodriver solver."""
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(_solve_cf_with_nodriver(url))
    finally:
        loop.close()


def _create_bypass_session(url, headers):
    """Try multiple strategies to get past Cloudflare and return (session, response)."""
    # Strategy 1: curl_cffi with different impersonate profiles
    for profile in IMPERSONATE_PROFILES:
        try:
            session = requests.Session(impersonate=profile)
            r = session.get(url=url, headers=headers, timeout=15)
            if not _is_cf_challenge(r):
                print(f"Connected with curl_cffi impersonate={profile}")
                return session, r
        except Exception as e:
            print(f"curl_cffi ({profile}) failed: {e}")

    print("Cloudflare challenge detected, attempting bypass...")

    # Strategy 2: cloudscraper (solves older Cloudflare JS challenges)
    try:
        import cloudscraper
        print("Trying cloudscraper bypass...")
        scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "darwin", "mobile": False},
        )
        r = scraper.get(url, headers=headers, timeout=20)
        if not _is_cf_challenge(r):
            print("Cloudflare bypassed via cloudscraper")
            return scraper, r
        print("cloudscraper did not bypass Cloudflare")
    except ImportError:
        print("cloudscraper not installed, skipping")
    except Exception as e:
        print(f"cloudscraper failed: {e}")

    # Strategy 3: nodriver (undetectable Chrome via CDP)
    try:
        print("Trying nodriver (undetectable Chrome)...")
        cookie_dict, html, ua = _solve_cf_nodriver_sync(url)
        if cookie_dict and html:
            req_headers = dict(headers)
            req_headers["User-Agent"] = ua
            session = requests.Session(impersonate="chrome")
            for name, value in cookie_dict.items():
                session.cookies.set(name, value)
            r = session.get(url=url, headers=req_headers, timeout=15)
            if not _is_cf_challenge(r):
                print("Cloudflare bypassed via nodriver cookies + curl_cffi")
                return session, r
            print("nodriver cookies did not work with curl_cffi, using page content directly")
    except ImportError:
        print("nodriver not installed, skipping")
    except Exception as e:
        print(f"nodriver failed: {e}")

    return None, None


def query_status(location, application_num, passport_number, surname, captchaHandle: CaptchaHandle = OnnxCaptchaHandle("captcha.onnx")):
    failCount = 0
    result = {
        "success": False,
    }
    backupTime = 5

    while failCount < 5:
        if failCount > 0:
            print(f"Retrying... Attempt {failCount + 1} / 5 in {backupTime} seconds")
            time.sleep(backupTime)
        failCount += 1
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en,zh-CN;q=0.9,zh;q=0.8",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Host": "ceac.state.gov",
        }

        ROOT = "https://ceac.state.gov"
        page_url = f"{ROOT}/ceacstattracker/status.aspx?App=NIV"

        try:
            session, r = _create_bypass_session(page_url, headers)
            if session is None:
                print("All Cloudflare bypass strategies failed")
                continue
        except Exception as e:
            print(e)
            continue

        soup = BeautifulSoup(r.text, features="lxml")

        # Find captcha image
        captcha = soup.find(name="img", id="c_status_ctl00_contentplaceholder1_defaultcaptcha_CaptchaImage")
        if not captcha:
            print("Captcha image not found on page")
            continue

        image_url = ROOT + captcha["src"]
        img_resp = session.get(image_url)

        # Resolve captcha
        captcha_num = captchaHandle.solve(img_resp.content)
        print(f"Captcha solved: {captcha_num}")

        # Find the correct value for the location dropdown
        location_dropdown = soup.find("select", id="Location_Dropdown")
        location_value = None
        for option in location_dropdown.find_all("option"):
            if location in option.text:
                location_value = option["value"]
                break

        if not location_value:
            print("Location not found in dropdown options.")
            return {"success": False}

        # Fill form
        def update_from_current_page(cur_page, name, data):
            ele = cur_page.find(name="input", attrs={"name": name})
            if ele:
                data[name] = ele["value"]

        data = {
            "ctl00$ToolkitScriptManager1": "ctl00$ContentPlaceHolder1$UpdatePanel1|ctl00$ContentPlaceHolder1$btnSubmit",
            "ctl00_ToolkitScriptManager1_HiddenField": ";;AjaxControlToolkit, Version=4.1.40412.0, Culture=neutral, PublicKeyToken=28f01b0e84b6d53e:en-US:acfc7575-cdee-46af-964f-5d85d9cdcf92:de1feab2:f9cec9bc:a67c2700:f2c8e708:8613aea7:3202a5a2:ab09e3fe:87104b7c:be6fb298",
            "__EVENTTARGET": "ctl00$ContentPlaceHolder1$btnSubmit",
            "__EVENTARGUMENT": "",
            "__LASTFOCUS": "",
            "__VIEWSTATE": "8GJOG5GAuT1ex7KX3jakWssS08FPVm5hTO2feqUpJk8w5ukH4LG/o39O4OFGzy/f2XLN8uMeXUQBDwcO9rnn5hdlGUfb2IOmzeTofHrRNmB/hwsFyI4mEx0mf7YZo19g",
            "__VIEWSTATEGENERATOR": "DBF1011F",
            "__VIEWSTATEENCRYPTED": "",
            "ctl00$ContentPlaceHolder1$Visa_Application_Type": "NIV",
            "ctl00$ContentPlaceHolder1$Location_Dropdown": location_value,  # Use the correct value
            "ctl00$ContentPlaceHolder1$Visa_Case_Number": application_num,
            "ctl00$ContentPlaceHolder1$Captcha": captcha_num,
            "ctl00$ContentPlaceHolder1$Passport_Number": passport_number,
            "ctl00$ContentPlaceHolder1$Surname": surname,
            "LBD_VCID_c_status_ctl00_contentplaceholder1_defaultcaptcha": "a81747f3a56d4877bf16e1a5450fb944",
            "LBD_BackWorkaround_c_status_ctl00_contentplaceholder1_defaultcaptcha": "1",
            "__ASYNCPOST": "true",
        }

        fields_need_update = [
            "__VIEWSTATE",
            "__VIEWSTATEGENERATOR",
            "LBD_VCID_c_status_ctl00_contentplaceholder1_defaultcaptcha",
        ]
        for field in fields_need_update:
            update_from_current_page(soup, field, data)

        try:
            r = session.post(url=f"{ROOT}/ceacstattracker/status.aspx", headers=headers, data=data)
        except Exception as e:
            print(e)
            continue

        soup = BeautifulSoup(r.text, features="lxml")
        status_tag = soup.find("span", id="ctl00_ContentPlaceHolder1_ucApplicationStatusView_lblStatus")
        if not status_tag:
            continue

        application_num_returned = soup.find("span", id="ctl00_ContentPlaceHolder1_ucApplicationStatusView_lblCaseNo").string
        assert application_num_returned == application_num
        status = status_tag.string
        visa_type = soup.find("span", id="ctl00_ContentPlaceHolder1_ucApplicationStatusView_lblAppName").string
        case_created = soup.find("span", id="ctl00_ContentPlaceHolder1_ucApplicationStatusView_lblSubmitDate").string
        case_last_updated = soup.find("span", id="ctl00_ContentPlaceHolder1_ucApplicationStatusView_lblStatusDate").string
        description = soup.find("span", id="ctl00_ContentPlaceHolder1_ucApplicationStatusView_lblMessage").string

        result.update({
            "success": True,
            "time": str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())),
            "visa_type": visa_type,
            "status": status,
            "case_created": case_created,
            "case_last_updated": case_last_updated,
            "description": description,
            "application_num": application_num_returned,
            "application_num_origin": application_num
        })
        break

    return result
