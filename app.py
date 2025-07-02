import asyncio
import re
from typing import List, Dict, Set
from fastapi import FastAPI, Query, HTTPException
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
import logging
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# Setup logging with detailed output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI()

# Add these after the existing regex patterns
ignore_if_url_contains = [
    # Common asset/content folders
    "wp-content", "wp-includes", "skin/frontend", "/assets/", "/themes/", "/static/", "/media/", "/images/", "/img/",

    "https://facebook.com", "https://googlemanager.com", "https://static.klaviyo.com", "static.klaviyo.com", "https://content-autofill.googleapis.com",
    "content-autofill.googleapis.com", "https://www.google.com", "https://googleads.g.doubleclick.net", "googleads.g.doubleclick.net",
    "https://www.googletagmanager.com", "googletagmanager.com", "https://www.googleadservices.com", "googleadservices.com", "https://fonts.googleapis.com",
    "fonts.googleapis.com", "http://clients2.google.com", "clients2.google.com", "https://analytics.google.com", "hanalytics.google.com",
    
    # Analytics & marketing scripts
    "googleapis", "gstatic", "googletagmanager", "google-analytics", "analytics", "doubleclick.net", 
    "facebook.net", "fbcdn", "pixel.", "tiktokcdn", "matomo", "segment.io", "clarity.ms", "mouseflow", "hotjar", 
    
    # Fonts, icons, visual only
    "fonts.", "fontawesome", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".ico", ".svg",
    
    # CDN & framework scripts
    "cdn.jsdelivr.net", "cloudflareinsights.com", "cdnjs", "bootstrapcdn", "polyfill.io", 
    "jsdelivr.net", "unpkg.com", "yastatic.net", "akamai", "fastly", 
    
    # Media, tracking images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg", ".ico", 
    
    # Useless scripts/styles
    ".css", ".scss", ".less", ".map", ".js", "main.js", "bundle.js", "common.js", "theme.js", "style.css", "custom.css",

    # Other non-payment known paths
    "/favicon", "/robots.txt", "/sitemap", "/manifest", "/rss", "/feed", "/help", "/support", "/about", "/terms", "/privacy",
]

NON_HTML_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.icon', '.img'}

SKIP_DOMAINS = {
    'help.ko-fi.com', 'static.cloudflareinsights.com', 'twitter.com', 'facebook.com', 'youtube.com',
    'https://facebook.com', 'https://googlemanager.com', 'https://static.klaviyo.com', 'static.klaviyo.com',
    'https://content-autofill.googleapis.com', 'content-autofill.googleapis.com', 'https://www.google.com',
    'https://googleads.g.doubleclick.net', 'googleads.g.doubleclick.net', 'https://www.googletagmanager.com',
    'googletagmanager.com', 'https://www.googleadservices.com', 'googleadservices.com', 'https://fonts.googleapis.com',
    'fonts.googleapis.com', 'http://clients2.google.com', 'clients2.google.com', 'https://analytics.google.com',
    'hanalytics.google.com', 'https://twitter.com', 'https://x.com'
}

# Regex patterns
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
    "reCaptcha": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'g-recaptcha', r'recaptcha/api\.js', r'data-sitekey', r'nocaptcha',
        r'recaptcha\.net', r'www\.google\.com/recaptcha', r'grecaptcha\.execute',
        r'grecaptcha\.render', r'grecaptcha\.ready', r'recaptcha-token'
    ]],
    "hCaptcha": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'hcaptcha', r'assets\.hcaptcha\.com', r'hcaptcha\.com/1/api\.js',
        r'data-hcaptcha-sitekey', r'js\.stripe\.com/v3/hcaptcha-invisible',
        r'hcaptcha-invisible', r'hcaptcha\.execute'
    ]],
    "Turnstile": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'turnstile', r'challenges\.cloudflare\.com', r'cf-turnstile-response',
        r'data-sitekey', r'__cf_chl_', r'cf_clearance'
    ]],
    "Arkose Labs": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'arkose-labs', r'funcaptcha', r'client-api\.arkoselabs\.com',
        r'fc-token', r'fc-widget', r'arkose', r'press and hold', r'funcaptcha\.com'
    ]],
    "GeeTest": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'geetest', r'gt_captcha_obj', r'gt\.js', r'geetest_challenge',
        r'geetest_validate', r'geetest_seccode'
    ]],
    "BotDetect": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'botdetectcaptcha', r'BotDetect', r'BDC_CaptchaImage', r'CaptchaCodeTextBox'
    ]],
    "KeyCAPTCHA": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'keycaptcha', r'kc_submit', r'kc__widget', r's_kc_cid'
    ]],
    "Anti Bot Detection": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'fingerprintjs', r'js\.challenge', r'checking your browser',
        r'verify you are human', r'please enable javascript and cookies',
        r'sec-ch-ua-platform'
    ]],
    "Captcha": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'captcha-container', r'captcha-box', r'captcha-frame', r'captcha_input',
        r'id="captcha"', r'class="captcha"', r'iframe.+?captcha',
        r'data-captcha-sitekey'
    ]]
}

CLOUDFLARE_INDICATORS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'cloudflare', r'cf-ray', r'cf-chl-.*', r'__cf_bm', r'cf_clearance',
    r'cdn-cgi', r'challenge\.cloudflare\.com', r'Just a moment\.\.\.',
    r'Checking your browser before accessing'
]]

PAYMENT_INDICATOR_REGEX = [
    re.compile(rf"{kw}", re.IGNORECASE)
    for kw in [
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
        "donate", "support", "pledge", "give"
    ]
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
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
    
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


def should_skip_url(url: str) -> bool:
    """
    Check if a URL should be skipped based on filtering criteria.
    Returns True if the URL should be skipped, False otherwise.
    """
    from urllib.parse import urlparse

    # Check for non-HTML extensions
    if any(url.lower().endswith(ext) for ext in NON_HTML_EXTENSIONS):
        return True

    # Check for ignored keywords in URL
    if any(keyword in url.lower() for keyword in ignore_if_url_contains):
        return True

    # Check for skipped domains
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if domain in SKIP_DOMAINS or url.lower() in SKIP_DOMAINS:
        return True

    return False

# Async HTML fetching using Selenium Wire with iframe support
async def fetch_html(url: str, semaphore: asyncio.Semaphore, driver, timeout: int = 15) -> tuple:
    async with semaphore:
        try:
            driver.get(url)
            driver.wait_for_request(url, timeout=timeout)
            # Wait for dynamic content
            await asyncio.sleep(2)  # 2-second delay for late-loaded content
            # Collect HTML from main page and iframes
            html = driver.page_source
            # Switch to each iframe and append its content
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            for iframe in iframes:
                try:
                    driver.switch_to.frame(iframe)
                    html += driver.page_source
                    driver.switch_to.default_content()
                except Exception as e:
                    logger.warning(f"Failed to process iframe on {url}: {str(e)}")
                    continue
            return url, html
        except Exception as e:
            logger.error(f"Failed to fetch {url} with Selenium Wire: {str(e)}")
            return url, None

# Parse HTML for links
def parse_links(html: str, base_url: str) -> Set[str]:
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        full_url = urljoin(base_url, href)
        if should_skip_url(full_url):
            continue
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

    # Check HTML and network requests for gateways and 3D secure
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

# Main crawling function with corrected key
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
    if should_skip_url(start_url):
        logger.warning(f"Starting URL {start_url} matches skip criteria, but crawling anyway")
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
                        tasks.append(fetch_html(url, semaphore, driver))
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for url, html in responses:
                    if not html:
                        logger.warning(f"No HTML for {url}, skipping")
                        continue
                    links = parse_links(html, url)
                    filtered_links = {link for link in links if not should_skip_url(link)}
                    to_visit.update(filtered_links - visited)
                    
                    # Analyze with Selenium Wire
                    try:
                        driver.get(url)
                        driver.wait_for_request(url, timeout=10)
                        page_result = analyze_page(driver.page_source, driver.requests, url)
                        
                        # Aggregate results with error handling
                        try:
                            result["payment_gateways"].update(page_result.get("payment_gateways", []))
                            result["3d_secure"].update(page_result.get("3d_secure", []))
                            result["captcha"].update(page_result.get("captcha", []))
                            if page_result.get("cloudflare", False):
                                result["cloudflare"] = True
                        except Exception as e:
                            logger.error(f"Error aggregating results for {url}: {str(e)}")
                            continue
                        
                        driver.requests.clear()  # Clear requests to save memory
                    except Exception as e:
                        logger.error(f"Error analyzing {url} with Selenium Wire: {str(e)}")
                        continue
                
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
