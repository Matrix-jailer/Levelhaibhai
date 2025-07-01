import asyncio
import logging
import time
import re
from playwright_stealth import stealth_async
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, HttpUrl
from concurrent.futures import ThreadPoolExecutor
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
        r'stripe\.com', r'api\.stripe\.com/v1', r'js\.stripe\.com', r'stripe\.js', r'stripe\.min\.js',
        r'client_secret', r'payment_intent', r'data-stripe', r'stripe-payment-element',
        r'stripe-elements', r'stripe-checkout', r'hooks\.stripe\.com', r'm\.stripe\.network',
        r'stripe__input', r'stripe-card-element', r'stripe-v3ds', r'confirmCardPayment',
        r'createPaymentMethod', r'stripePublicKey', r'stripe\.handleCardAction',
        r'elements\.create', r'js\.stripe\.com/v3/hcaptcha-invisible', r'js\.stripe\.com/v3',
        r'stripe\.createToken', r'stripe-payment-request', r'stripe__frame',
        r'api\.stripe\.com/v1/payment_methods', r'js\.stripe\.com', r'api\.stripe\.com/v1/tokens',
        r'stripe\.com/docs', r'checkout\.stripe\.com', r'stripe-js', r'stripe-redirect',
        r'stripe-payment', r'stripe\.network', r'stripe-checkout\.js'
    ]],
    "paypal": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.paypal\.com', r'paypal\.com', r'paypal-sdk\.com', r'paypal\.js', r'paypalobjects\.com', r'paypal_express_checkout', r'e\.PAYPAL_EXPRESS_CHECKOUT',
        r'paypal-button', r'paypal-checkout-sdk', r'paypal-sdk\.js', r'paypal-smart-button', r'paypal_express_checkout/api',
        r'paypal-rest-sdk', r'paypal-transaction', r'itch\.io/api-transaction/paypal',
        r'PayPal\.Buttons', r'paypal\.Buttons', r'data-paypal-client-id', r'paypal\.com/sdk/js',
        r'paypal\.Order\.create', r'paypal-checkout-component', r'api-m\.paypal\.com', r'paypal-funding',
        r'paypal-hosted-fields', r'paypal-transaction-id', r'paypal\.me', r'paypal\.com/v2/checkout',
        r'paypal-checkout', r'paypal\.com/api', r'sdk\.paypal\.com', r'gotopaypalexpresscheckout'
    ]],
    "braintree": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.braintreegateway\.com/v1', r'braintreepayments\.com', r'js\.braintreegateway\.com',
        r'client_token', r'braintree\.js', r'braintree-hosted-fields', r'braintree-dropin', r'braintree-v3',
        r'braintree-client', r'braintree-data-collector', r'braintree-payment-form', r'braintree-3ds-verify',
        r'client\.create', r'braintree\.min\.js', r'assets\.braintreegateway\.com', r'braintree\.setup',
        r'data-braintree', r'braintree\.tokenize', r'braintree-dropin-ui', r'braintree\.com'
    ]],
    "adyen": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkoutshopper-live\.adyen\.com', r'adyen\.com/hpp', r'adyen\.js', r'data-adyen',
        r'adyen-checkout', r'adyen-payment', r'adyen-components', r'adyen-encrypted-data',
        r'adyen-cse', r'adyen-dropin', r'adyen-web-checkout', r'live\.adyen-services\.com',
        r'adyen\.encrypt', r'checkoutshopper-test\.adyen\.com', r'adyen-checkout__component',
        r'adyen\.com/v1', r'adyen-payment-method', r'adyen-action', r'adyen\.min\.js', r'adyen\.com'
    ]],
    "authorize.net": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'authorize\.net/gateway/transact\.dll', r'js\.authorize\.net/v1/Accept\.js', r'js\.authorize\.net',
        r'anet\.js', r'data-authorize', r'authorize-payment', r'apitest\.authorize\.net',
        r'accept\.authorize\.net', r'api\.authorize\.net', r'authorize-hosted-form',
        r'merchantAuthentication', r'data-api-login-id', r'data-client-key', r'Accept\.dispatchData',
        r'api\.authorize\.net/xml/v1', r'accept\.authorize\.net/payment', r'authorize\.net/profile'
    ]],
    "square": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'squareup\.com', r'js\.squarecdn\.com', r'square\.js', r'data-square', r'square-payment-form',
        r'square-checkout-sdk', r'connect\.squareup\.com', r'square\.min\.js', r'squarecdn\.com',
        r'squareupsandbox\.com', r'sandbox\.web\.squarecdn\.com', r'square-payment-flow', r'square\.card',
        r'squareup\.com/payments', r'data-square-application-id', r'square\.createPayment'
    ]],
    "klarna": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'klarna\.com', r'js\.klarna\.com', r'klarna\.js', r'data-klarna', r'klarna-checkout',
        r'klarna-onsite-messaging', r'playground\.klarna\.com', r'klarna-payments', r'klarna\.min\.js',
        r'klarna-order-id', r'klarna-checkout-container', r'klarna-load', r'api\.klarna\.com'
    ]],
    "checkout.com": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.checkout\.com', r'cko\.js', r'data-checkout', r'checkout-sdk', r'checkout-payment',
        r'js\.checkout\.com', r'secure\.checkout\.com', r'checkout\.frames\.js', r'api\.sandbox\.checkout\.com',
        r'cko-payment-token', r'checkout\.init', r'cko-hosted', r'checkout\.com/v2', r'cko-card-token'
    ]],
    "razorpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.razorpay\.com', r'razorpay\.js', r'data-razorpay', r'razorpay-checkout',
        r'razorpay-payment-api', r'razorpay-sdk', r'razorpay-payment-button', r'razorpay-order-id',
        r'api\.razorpay\.com', r'razorpay\.min\.js', r'payment_box payment_method_razorpay',
        r'razorpay', r'cdn\.razorpay\.com', r'rzp_payment_icon\.svg', r'razorpay\.checkout',
        r'data-razorpay-key', r'razorpay_payment_id', r'checkout\.razorpay\.com/v1', r'razorpay-hosted'
    ]],
    "paytm": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'securegw\.paytm\.in', r'api\.paytm\.com', r'paytm\.js', r'data-paytm', r'paytm-checkout',
        r'paytm-payment-sdk', r'paytm-wallet', r'paytm\.allinonesdk', r'securegw-stage\.paytm\.in',
        r'paytm\.min\.js', r'paytm-transaction-id', r'paytm\.invoke', r'paytm-checkout-js',
        r'data-paytm-order-id'
    ]],
    "Shopify Payments": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.shopify\.com', r'data-shopify-payments', r'shopify-checkout-sdk', r'shopify-payment-api',
        r'shopify-sdk', r'shopify-express-checkout', r'shopify_payments\.js', r'checkout\.shopify\.com',
        r'shopify-payment-token', r'shopify\.card', r'shopify-checkout-api', r'data-shopify-checkout',
        r'shopify\.com/api'
    ]],
    "worldpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'secure\.worldpay\.com', r'worldpay\.js', r'data-worldpay', r'worldpay-checkout',
        r'worldpay-payment-sdk', r'worldpay-secure', r'secure-test\.worldpay\.com', r'worldpay\.min\.js',
        r'worldpay\.token', r'worldpay-payment-form', r'access\.worldpay\.com', r'worldpay-3ds',
        r'data-worldpay-token'
    ]],
    "2checkout": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'www\.2checkout\.com', r'2co\.js', r'data-2checkout', r'2checkout-payment', r'secure\.2co\.com',
        r'2checkout-hosted', r'api\.2checkout\.com', r'2co\.min\.js', r'2checkout\.token', r'2co-checkout',
        r'data-2co-seller-id', r'2checkout\.convertplus', r'secure\.2co\.com/v2'
    ]],
    "Amazon pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'payments\.amazon\.com', r'amazonpay\.js', r'data-amazon-pay', r'amazon-pay-button',
        r'amazon-pay-checkout-sdk', r'amazon-pay-wallet', r'amazon-checkout\.js', r'payments\.amazon\.com/v2',
        r'amazon-pay-token', r'amazon-pay-sdk', r'data-amazon-pay-merchant-id', r'amazon-pay-signin',
        r'amazon-pay-checkout-session'
    ]],
    "Apple pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'apple-pay\.js', r'data-apple-pay', r'apple-pay-button', r'apple-pay-checkout-sdk',
        r'apple-pay-session', r'apple-pay-payment-request', r'ApplePaySession', r'apple-pay-merchant-id',
        r'apple-pay-payment', r'apple-pay-sdk', r'data-apple-pay-token', r'apple-pay-checkout',
        r'apple-pay-domain'
    ]],
    "Google pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.google\.com', r'googlepay\.js', r'data-google-pay', r'google-pay-button',
        r'google-pay-checkout-sdk', r'google-pay-tokenization', r'payments\.googleapis\.com',
        r'google\.payments\.api', r'google-pay-token', r'google-pay-payment-method',
        r'data-google-pay-merchant-id', r'google-pay-checkout', r'google-pay-sdk'
    ]],
    "mollie": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.mollie\.com', r'mollie\.js', r'data-mollie', r'mollie-checkout', r'mollie-payment-sdk',
        r'mollie-components', r'mollie\.min\.js', r'profile\.mollie\.com', r'mollie-payment-token',
        r'mollie-create-payment', r'data-mollie-profile-id', r'mollie-checkout-form', r'mollie-redirect'
    ]],
    "opayo": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'live\.opayo\.eu', r'opayo\.js', r'data-opayo', r'opoayo-checkout', r'opayo-payment-sdk',
        r'opayo-form', r'test\.opayo\.eu', r'opayo\.min\.js', r'opayo-payment-token', r'opayo-3ds',
        r'data-opayo-merchant-id', r'opayo-hosted', r'opayo\.api'
    ]],
    "paddle": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.paddle\.com', r'paddle_button\.js', r'paddle\.js', r'data-paddle',
        r'paddle-checkout-sdk', r'paddle-product-id', r'api\.paddle\.com', r'paddle\.min\.js',
        r'paddle-checkout', r'data-paddle-vendor-id', r'paddle\.Checkout\.open', r'paddle-transaction-id',
        r'paddle-hosted'
    ]]
}

THREE_D_SECURE_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'three_d_secure', r'3dsecure', r'acs_url', r'acsurl', r'redirect',
    r'secure-auth', r'three_d_secure_usage', r'challenge', r'3ds', r'3ds1', r'3ds2', r'tds', r'tdsecure',
    r'3d-secure', r'three-d', r'3dcheck', r'3d-auth', r'three-ds',
    r'stripe\.com/3ds', r'm\.stripe\.network', r'hooks\.stripe\.com/3ds',
    r'paddle_frame', r'paddlejs', r'secure\.paddle\.com', r'buy\.paddle\.com',
    r'idcheck', r'garanti\.com\.tr', r'adyen\.com/hpp', r'adyen\.com/checkout',
    r'adyenpayments\.com/3ds', r'auth\.razorpay\.com', r'razorpay\.com/3ds',
    r'secure\.razorpay\.com', r'3ds\.braintreegateway\.com', r'verify\.3ds',
    r'checkout\.com/3ds', r'checkout\.com/challenge', r'3ds\.paypal\.com',
    r'authentication\.klarna\.com', r'secure\.klarna\.com/3ds'
]]

CAPTCHA_PATTERNS = {
    "reCaptcha": [
        "g-recaptcha", "recaptcha/api.js", "data-sitekey", "nocaptcha",
        "recaptcha.net", "www.google.com/recaptcha", "grecaptcha.execute",
        "grecaptcha.render", "grecaptcha.ready", "recaptcha-token"
    ],
    "hCaptcha": [
        "hcaptcha", "assets.hcaptcha.com", "hcaptcha.com/1/api.js",
        "data-hcaptcha-sitekey", "js.stripe.com/v3/hcaptcha-invisible", "hcaptcha-invisible", "hcaptcha.execute"
    ],
    "Turnstile": [
        "turnstile", "challenges.cloudflare.com", "cf-turnstile-response",
        "data-sitekey", "__cf_chl_", "cf_clearance"
    ],
    "Arkose Labs": [
        "arkose-labs", "funcaptcha", "client-api.arkoselabs.com",
        "fc-token", "fc-widget", "arkose", "press and hold", "funcaptcha.com"
    ],
    "GeeTest": [
        "geetest", "gt_captcha_obj", "gt.js", "geetest_challenge",
        "geetest_validate", "geetest_seccode"
    ],
    "BotDetect": [
        "botdetectcaptcha", "BotDetect", "BDC_CaptchaImage", "CaptchaCodeTextBox"
    ],
    "KeyCAPTCHA": [
        "keycaptcha", "kc_submit", "kc__widget", "s_kc_cid"
    ],
    "Anti Bot Detection": [
        "fingerprintjs", "js.challenge", "checking your browser",
        "verify you are human", "please enable javascript and cookies",
        "sec-ch-ua-platform"
    ],
    "Captcha": [
        "captcha-container", "captcha-box", "captcha-frame", "captcha_input",
        "id=\"captcha\"", "class=\"captcha\"", "iframe.+?captcha",
        "data-captcha-sitekey"
    ]
}

CAPTCHA_PATTERNS = {
    key: [re.compile(pat, re.IGNORECASE) for pat in patterns]
    for key, patterns in CAPTCHA_PATTERNS.items()
}

CLOUDFLARE_INDICATORS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'cloudflare', r'cf-ray', r'cf-chl-.*', r'__cf_bm', r'cf_clearance',
    r'cdn-cgi', r'challenge.cloudflare.com', r'Just a moment\.\.\.',
    r'Checking your browser before accessing'
]]

PAYMENT_INDICATOR_REGEX = [re.compile(rf"{kw}", re.IGNORECASE) for kw in [
    # Core purchase flow
        "cart", "checkout", "payment", "pay", "buy", "purchase", "order", "billing",
        "invoice", "transaction", "secure-checkout", "confirm-purchase", "complete-order",
        "place-order", "express-checkout", "quick-buy", "buy-now", "shop-now",

        # Subscription & upgrades
        "subscribe", "trial", "renew", "upgrade", "membership", "plans",

        # Promotions, coupons, gift cards
        "apply-coupon", "discount-code", "gift-card", "promo-code", "redeem-code",

        # Payment info/forms
        "payment-method", "payment-details", "payment-form",

        # Pricing pages
        "pricing", "plans", "pricing-plan",

        # BNPL / donate / support
        "donate", "support", "pledge", "give",
    ]
]
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
        html = await page.content()
        if hasattr(page, "frames"):
            for frame in page.frames:
                try:
                    frame_url = frame.url
                    if urlparse(url).netloc not in urlparse(frame_url).netloc:
                        continue
                    frame_html = await frame.content()
                    for gateway, patterns in GATEWAY_KEYWORDS.items():
                        if check_keywords(frame_html, patterns):
                            results["payment_gateways"].append(gateway)
                            if check_keywords(frame_html, THREE_D_SECURE_KEYWORDS):
                                results["3d_secure"].extend([
                                    kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(frame_html)
                                ])
                except Exception as iframe_err:
                    logger.warning(f"[Iframe] Skipped frame due to error: {iframe_err}")
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

async def crawl_url(link, context, visited, base_url, semaphore):
    results = []
    async with semaphore:
        if link in visited:
            return []
        visited.add(link)

        try:
            page = await context.new_page()
            await page.goto(link, timeout=15000, wait_until="networkidle")

            # ✅ Main page scan
            try:
                result = await check_page_content(page, link)
                results.append(result)
            except Exception as e:
                logger.warning(f"[Main Page] Failed to check content: {e}")


            # 🔍 Iframe scan
            for frame in page.frames:
                try:
                    frame_url = frame.url
                    if urlparse(link).netloc not in urlparse(frame_url).netloc:
                        continue
                    result = await check_page_content(frame, frame_url)
                    results.append(result)
                except Exception as e:
                    logger.warning(f"[Iframe] Failed to check iframe content: {e}")


            # ✅ Collect links for further crawling
            anchors = await page.eval_on_selector_all("a", "els => els.map(el => el.href)")
            for a in anchors:
                if base_url in a and a not in visited:
                    results.append(a)

            await page.close()
        except Exception as e:
            logger.error(f"[Crawl Error] {link}: {e}")

    return results


async def crawl_website(base_url: str) -> List[Dict[str, Any]]:
    """Crawl website and collect results."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        # Apply stealth to initial page
        page = await context.new_page()
        await stealth_async(page)  # ✅ Add this line
        await page.goto(base_url)        # optional: close it after patching context

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
    options.add_argument("--headless=new")  # ✅ Optional, stealthier than old headless
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--start-maximized")
    options.add_argument("--lang=en-US,en;q=0.9")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


    try:
        driver = webdriver.Chrome(options=options, seleniumwire_options={})
        driver.set_page_load_timeout(15)
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": """
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            window.chrome = { runtime: {} };
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4] });
            Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
            """
        })

        try:
            driver.get(url)
            logger.info(f"[Driver] Page loaded: {url}")
        except Exception as load_err:
            logger.warning(f"[Timeout] Page load skipped for {url}: {load_err}")
            return results  # Not [] — keep return type consistent

        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            logger.info(f"[Driver] DOM ready: {url}")
        except Exception as wait_err:
            logger.warning(f"[Wait] DOM not ready for {url}: {wait_err}")

        # Scroll to mid-page
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 2);")
        time.sleep(random.uniform(0.1, 0.3))

        # Inspect network traffic
        for request in driver.requests:
            try:
                request_content = (
                    (request.url or "") +
                    str(request.headers or "") +
                    str(request.body or "") +
                    str(request.response.body if request.response else "")
                )

                for gateway, patterns in GATEWAY_KEYWORDS.items():
                    if check_keywords(request_content, patterns):
                        results["payment_gateways"].append(gateway)

                        if check_keywords(request_content, THREE_D_SECURE_KEYWORDS):
                            results["3d_secure"].extend([
                                kw.pattern for kw in THREE_D_SECURE_KEYWORDS if kw.search(request_content)
                            ])

                for captcha_type, patterns in CAPTCHA_PATTERNS.items():
                    if check_keywords(request_content, patterns):
                        results["captcha"].append(captcha_type)

                if check_keywords(request_content, CLOUDFLARE_INDICATORS):
                    results["cloudflare"] = True

            except Exception as req_err:
                logger.debug(f"[Network Request Error] Skipped one request: {req_err}")

        # Deduplicate results
        results["payment_gateways"] = list(set(results["payment_gateways"]))
        results["3d_secure"] = list(set(results["3d_secure"]))
        results["captcha"] = list(set(results["captcha"]))

    except Exception as e:
        logger.error(f"Error in network inspection for {url}: {e}")

    finally:
        if 'driver' in locals() and driver:
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

@app.get("/gatecheck")
async def gatecheck_get(url: HttpUrl = Query(..., description="Target URL to scan")):
    """GET version of gatecheck, accepts ?url=https://example.com"""
    return await gatecheck(UrlRequest(url=url))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
