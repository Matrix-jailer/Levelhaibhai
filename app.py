import asyncio
import re
from typing import List, Dict, Set
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
import logging
from urllib.parse import urljoin, urlparse
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import json

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI()

# Pydantic model for input
class URLInput(BaseModel):
    url: str

# Regex patterns
GATEWAY_KEYWORDS = {
    "stripe": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'stripe\.com', r'api\.stripe\.com/v1', r'js\.stripe\.com'
    ]],
    "paypal": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'paypal\.com', r'paypalobjects\.com', r'api\.paypal\.com'
    ]],
    "apple_pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'applepay', r'apple-pay', r'webkit-payment'
    ]],
    "google_pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'googlepay', r'pay\.google\.com', r'payments\.google\.com'
    ]]
}

THREE_D_SECURE_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'three_d_secure', r'3dsecure', r'acs', r'acs_url'
]]

CAPTCHA_PATTERNS = {
    "reCaptcha": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'g-recaptcha', r'recaptcha/api\.js', r'data-sitekey', r'nocaptcha', r'recaptcha\.net'
    ]],
    "hCaptcha": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'hcaptcha', r'assets\.hcaptcha\.com', r'hcaptcha\.com/1/api\.js',
        r'data-hcaptcha-sitekey', r'js\.stripe\.com/v3/hcaptcha-invisible',
        r'hcaptcha-invisible', r'hcaptcha\.execute'
    ]]
}

CLOUDFLARE_INDICATORS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'cloudflare', r'cf-ray', r'cf-chl-.*', r'__cf_bm', r'cf_clearance',
    r'cdn-cgi', r'challenge\.cloudflare\.com', r'Just a moment\.\.\.',
    r'Checking your browser before accessing'
]]

PAYMENT_INDICATOR_REGEX = [
    re.compile(rf"{kw}", re.IGNORECASE)
    for kw in ["cart", "checkout", "payment", "buy", "purchase"]
]

# Selenium Wire setup
def get_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--start-maximized")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    
    driver = webdriver.Chrome(options=options, seleniumwire_options={})
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        "source": """
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        window.chrome = { runtime: {} };
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
        Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
        """
    })
    return driver

# Async HTML fetching
async def fetch_html(url: str, semaphore: asyncio.Semaphore, timeout: int = 10) -> tuple:
    async with semaphore:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout) as response:
                    if response.status == 200:
                        return url, await response.text()
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
    return url, None

# Parse HTML for links
def parse_links(html: str, base_url: str) -> Set[str]:
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        full_url = urljoin(base_url, href)
        if any(regex.search(full_url) for regex in PAYMENT_INDICATOR_REGEX):
            links.add(full_url)
    return links

# Analyze page for keywords
def analyze_page(html: str, requests: List, url: str) -> Dict:
    result = {
        "payment_gateways": [],
        "3d_secure": [],
        "captcha": [],
        "cloudflare": False
    }

    # Check HTML for gateways and 3D secure
    for gateway, patterns in GATEWAY_KEYWORDS.items():
        for pattern in patterns:
            if pattern.search(html) or any(pattern.search(str(req.url)) for req in requests):
                result["payment_gateways"].append(gateway)
                # Check for 3D secure only if gateway is found
                if gateway in result["payment_gateways"]:
                    for td_pattern in THREE_D_SECURE_KEYWORDS:
                        if td_pattern.search(html) or any(td_pattern.search(str(req.url)) for req in requests):
                            result["3d_secure"].append(td_pattern.pattern)

    # Check for CAPTCHA
    for captcha_type, patterns in CAPTCHA_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(html) or any(pattern.search(str(req.url)) for req in requests):
                result["captcha"].append(captcha_type)

    # Check for Cloudflare
    for cf_pattern in CLOUDFLARE_INDICATORS:
        if cf_pattern.search(html) or any(cf_pattern.search(str(req.url)) for req in requests):
            result["cloudflare"] = True
            break

    return result

# Main crawling function
async def crawl_website(start_url: str, max_pages: int = 50, concurrency: int = 10) -> Dict:
    result = {
        "url": start_url,
        "payment_gateways": set(),
        "3d_secure": set(),
        "captcha": set(),
        "cloudflare": False
    }
    
    visited = set()
    to_visit = {start_url}
    semaphore = asyncio.Semaphore(concurrency)
    driver = get_driver()
    
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            while to_visit and len(visited) < max_pages:
                tasks = []
                for url in list(to_visit)[:concurrency]:
                    to_visit.remove(url)
                    if url not in visited:
                        visited.add(url)
                        tasks.append(fetch_html(url, semaphore))
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for url, html in responses:
                    if not html:
                        continue
                        
                    # Parse links for crawling
                    links = parse_links(html, url)
                    to_visit.update(links - visited)
                    
                    # Analyze with Selenium Wire
                    driver.get(url)
                    driver.wait_for_request(url, timeout=10)
                    page_result = analyze_page(driver.page_source, driver.requests, url)
                    
                    # Aggregate results
                    result["payment_gateways"].update(page_result["payment_gateways"])
                    result["3d_secure"].update(page_result["3d_secure"])
                    result["captcha"].update(page_result["captcha"])
                    if page_result["cloudflare"]:
                        result["cloudflare"] = True
                        
                    driver.requests.clear()  # Clear requests to save memory
                
    except Exception as e:
        logger.error(f"Error crawling {start_url}: {e}")
    finally:
        driver.quit()
    
    # Convert sets to lists for JSON output
    result["payment_gateways"] = list(result["payment_gateways"])
    result["3d_secure"] = list(result["3d_secure"])
    result["captcha"] = list(result["captcha"])
    
    return result

# FastAPI endpoint
@app.get("/gatecheck")
async def gatecheck(url: str = Query(..., description="The URL to analyze")):
    try:
        result = await crawl_website(url)
        return {"status": "done", "result": result}
    except Exception as e:
        logger.error(f"API error for {url}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
