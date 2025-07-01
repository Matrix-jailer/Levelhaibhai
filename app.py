import asyncio
import logging
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
from fastapi import FastAPI, HTTPException
from pydantic import HttpUrl
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
import json
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("crawler.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Define regex patterns
GATEWAY_KEYWORDS = {
    "stripe": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'stripe\.com', r'api\.stripe\.com/v1', r'js\.stripe\.com'
    ]]
}

THREE_D_SECURE_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'three_d_secure', r'3dsecure', r'acs', r'acs_url'
]]

CAPTCHA_PATTERNS = {
    "reCaptcha": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'g-recaptcha', r'recaptcha/api.js', r'data-sitekey', r'nocaptcha', r'recaptcha.net'
    ]],
    "hCaptcha": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'hcaptcha', r'assets.hcaptcha.com', r'hcaptcha.com/1/api.js',
        r'data-hcaptcha-sitekey', r'js.stripe.com/v3/hcaptcha-invisible',
        r'hcaptcha-invisible', r'hcaptcha.execute'
    ]]
}

CLOUDFLARE_INDICATORS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'cloudflare', r'cf-ray', r'cf-chl-.*', r'__cf_bm', r'cf_clearance',
    r'cdn-cgi', r'challenge.cloudflare.com', r'Just a moment\.\.\.',
    r'Checking your browser before accessing'
]]

PAYMENT_INDICATOR_REGEX = [re.compile(rf"{kw}", re.IGNORECASE) for kw in [
    "cart", "checkout", "payment", "buy", "purchase"
]]

# FastAPI app
app = FastAPI()

# Pydantic model for URL validation
from pydantic import BaseModel

class UrlRequest(BaseModel):
    url: HttpUrl

# Helper functions
def is_valid_url(url: str, base_domain: str) -> bool:
    """Check if URL is valid and belongs to the same domain."""
    parsed_base = urlparse(base_domain)
    parsed_url = urlparse(url)
    return (
        parsed_url.scheme in ["http", "https"] and
        parsed_url.netloc == parsed_base.netloc and
        not any(ext in parsed_url.path.lower() for ext in [".pdf", ".jpg", ".png", ".js", ".css"])
    )

async def human_like_behavior(page) -> None:
    """Simulate human-like behavior to avoid detection."""
    try:
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await page.mouse.move(random.randint(100, 500), random.randint(100, 500))
        await asyncio.sleep(random.uniform(0.1, 0.2))
    except Exception as e:
        logger.warning(f"Human-like behavior failed: {e}")

def check_keywords(content: str, patterns: List[re.Pattern]) -> bool:
    """Check if any regex pattern matches in content."""
    return any(pattern.search(content) for pattern in patterns)

async def check_page_content(page, url: str) -> Dict[str, Any]:
    """Check page for keywords in specified locations."""
    results = {
        "payment_gateways": [],
        "3d_secure": [],
        "captcha": [],
        "cloudflare": False
    }

    try:
        # Main HTML
        html = await page.content()
        for gateway, patterns in GATEWAY_KEYWORDS.items():
            if check_keywords(html, patterns):
                results["payment_gateways"].append(gateway)
                # Check 3D Secure only if gateway found
                if check_keywords(html, THREE_D_SECURE_KEYWORDS):
                    results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(html)])

        for captcha_type, patterns in CAPTCHA_PATTERNS.items():
            if check_keywords(html, patterns):
                results["captcha"].append(captcha_type)

        if check_keywords(html, CLOUDFLARE_INDICATORS):
            results["cloudflare"] = True

        # Links and Buttons
        elements = await page.query_selector_all('a, button')
        for element in elements:
            text = await element.inner_text() or ""
            href = await element.get_attribute('href') or ""
            for gateway, patterns in GATEWAY_KEYWORDS.items():
                if check_keywords(text + href, patterns):
                    results["payment_gateways"].append(gateway)
                    if check_keywords(text + href, THREE_D_SECURE_KEYWORDS):
                        results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(text + href)])

        # Forms
        forms = await page.query_selector_all('form')
        for form in forms:
            form_html = await form.inner_html()
            for gateway, patterns in GATEWAY_KEYWORDS.items():
                if check_keywords(form_html, patterns):
                    results["payment_gateways"].append(gateway)
                    if check_keywords(form_html, THREE_D_SECURE_KEYWORDS):
                        results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(form_html)])

        # Shadow DOM
        shadow_content = await page.evaluate("""
            () => {
                let content = '';
                document.querySelectorAll('*').forEach(el => {
                    if (el.shadowRoot) content += el.shadowRoot.innerHTML;
                });
                return content;
            }
        """)
        for gateway, patterns in GATEWAY_KEYWORDS.items():
            if check_keywords(shadow_content, patterns):
                results["payment_gateways"].append(gateway)
                if check_keywords(shadow_content, THREE_D_SECURE_KEYWORDS):
                    results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(shadow_content)])

        # Iframes
        for frame in page.frames:
            frame_html = await frame.content()
            for gateway, patterns in GATEWAY_KEYWORDS.items():
                if check_keywords(frame_html, patterns):
                    results["payment_gateways"].append(gateway)
                    if check_keywords(frame_html, THREE_D_SECURE_KEYWORDS):
                        results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(frame_html)])

        # Scripts
        scripts = await page.evaluate("Array.from(document.scripts).map(s => s.src || s.innerHTML)")
        scripts_content = " ".join(scripts)
        for gateway, patterns in GATEWAY_KEYWORDS.items():
            if check_keywords(scripts_content, patterns):
                results["payment_gateways"].append(gateway)
                if check_keywords(scripts_content, THREE_D_SECURE_KEYWORDS):
                    results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(scripts_content)])

        # Event Handlers
        event_handlers = await page.evaluate("Array.from(document.querySelectorAll('[onclick]')).map(el => el.getAttribute('onclick'))")
        event_content = " ".join(event_handlers)
        for gateway, patterns in GATEWAY_KEYWORDS.items():
            if check_keywords(event_content, patterns):
                results["payment_gateways"].append(gateway)
                if check_keywords(event_content, THREE_D_SECURE_KEYWORDS):
                    results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(event_content)])

        # Deduplicate results
        results["payment_gateways"] = list(set(results["payment_gateways"]))
        results["3d_secure"] = list(set(results["3d_secure"]))
        results["captcha"] = list(set(results["captcha"]))

    except Exception as e:
        logger.error(f"Error checking content for {url}: {e}")

    return results

async def crawl_url(url: str, context, visited: set, base_url: str, semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
    """Crawl a single URL and extract keywords and links."""
    async with semaphore:
        results = []
        if url in visited:
            return results
        visited.add(url)

        try:
            page = await context.new_page()
            await page.set_extra_http_headers({
                "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            })
            await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            await human_like_behavior(page)

            # Check page content
            page_results = await check_page_content(page, url)
            results.append({"url": url, **page_results})

            # Extract payment-related links
            links = await page.query_selector_all('a')
            hrefs = [await link.get_attribute('href') for link in links]
            payment_urls = [
                urljoin(url, href) for href in hrefs
                if href and is_valid_url(urljoin(url, href), base_url) and
                any(pattern.search(urljoin(url, href)) for pattern in PAYMENT_INDICATOR_REGEX)
            ]
            payment_urls = list(set(payment_urls))[:50]  # Limit to 50 URLs

            await page.close()
            return results + payment_urls
        except PlaywrightTimeoutError:
            logger.warning(f"Timeout crawling {url}")
            return results
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return results

async def crawl_website(base_url: str) -> List[Dict[str, Any]]:
    """Crawl website and collect results."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        semaphore = asyncio.Semaphore(10)  # Limit to 10 concurrent tasks
        visited = set()
        to_crawl = [base_url]
        all_results = []

        while to_crawl:
            tasks = [crawl_url(url, context, visited, base_url, semaphore) for url in to_crawl[:10]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            to_crawl = []
            for result in results:
                if isinstance(result, list):
                    for item in result:
                        if isinstance(item, dict):
                            all_results.append(item)
                        elif isinstance(item, str):
                            to_crawl.append(item)

        await browser.close()
        return all_results

def check_network_requests(url: str) -> Dict[str, Any]:
    """Inspect network requests using Selenium Wire."""
    results = {
        "payment_gateways": [],
        "3d_secure": [],
        "captcha": [],
        "cloudflare": False
    }

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    try:
        driver = webdriver.Chrome(options=options, seleniumwire_options={})
        driver.set_page_load_timeout(10)
        driver.get(url)

        # Simulate human behavior
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 2);")
        time.sleep(random.uniform(0.1, 0.3))

        # Check network requests
        for request in driver.requests:
            request_content = (request.url + str(request.headers) + str(request.body) + str(request.response.body if request.response else ""))
            for gateway, patterns in GATEWAY_KEYWORDS.items():
                if check_keywords(request_content, patterns):
                    results["payment_gateways"].append(gateway)
                    if check_keywords(request_content, THREE_D_SECURE_KEYWORDS):
                        results["3d_secure"].extend([kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(request_content)])

            for captcha_type, patterns in CAPTCHA_PATTERNS.items():
                if check_keywords(request_content, patterns):
                    results["captcha"].append(captcha_type)

            if check_keywords(request_content, CLOUDFLARE_INDICATORS):
                results["cloudflare"] = True

        results["payment_gateways"] = list(set(results["payment_gateways"]))
        results["3d_secure"] = list(set(results["3d_secure"]))
        results["captcha"] = list(set(results["captcha"]))

    except Exception as e:
        logger.error(f"Error in network inspection for {url}: {e}")
    finally:
        driver.quit()

    return results

@app.post("/gatecheck")
async def gatecheck(request: UrlRequest):
    """FastAPI endpoint to check website for payment, 3D secure, CAPTCHA, and Cloudflare."""
    try:
        base_url = str(request.url)
        logger.info(f"Starting crawl for {base_url}")

        # Crawl website with Playwright
        crawl_results = await crawl_website(base_url)

        # Network inspection with Selenium Wire
        network_results = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(check_network_requests, result["url"]) for result in crawl_results if "url" in result]
            network_results = [future.result() for future in futures]

        # Combine results
        combined_results = {
            "url": base_url,
            "payment_gateways": [],
            "3d_secure": [],
            "captcha": [],
            "cloudflare": False
        }

        for result in crawl_results + network_results:
            if "payment_gateways" in result:
                combined_results["payment_gateways"].extend(result["payment_gateways"])
            if "3d_secure" in result:
                combined_results["3d_secure"].extend(result["3d_secure"])
            if "captcha" in result:
                combined_results["captcha"].extend(result["captcha"])
            if result.get("cloudflare"):
                combined_results["cloudflare"] = True

        combined_results["payment_gateways"] = list(set(combined_results["payment_gateways"]))
        combined_results["3d_secure"] = list(set(combined_results["3d_secure"]))
        combined_results["captcha"] = list(set(combined_results["captcha"]))

        logger.info(f"Crawl completed for {base_url}")
        return {"status": "done", "result": combined_results}
    except Exception as e:
        logger.error(f"Error processing {base_url}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
