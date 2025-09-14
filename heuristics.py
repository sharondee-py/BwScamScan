from urllib.parse import urlparse, unquote, parse_qs
import ipaddress
import re
import difflib
import requests
import json
from config import GOOGLE_SAFE_BROWSING_API_KEY, KNOWN_BRANDS, HIGH_RISK_TLDS, LOW_RISK_TLDS, COMPANY_PAGES
from urllib.parse import urlencode

# ==================== CORE URL ANALYSIS FUNCTIONS ====================

def is_ip_address(domain):
    """Check if the domain is an IP address."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def get_domain(url):
    """Extract the domain from a URL."""
    parsed_url = urlparse(url)
    return parsed_url.netloc

def try_extract_clean_url(url):
    """
    Attempts to extract a clean URL from inside known tracking redirects.
    Returns the clean URL if found, otherwise returns the original URL.
    """
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc.lower()
    query_params = parse_qs(parsed_url.query)

    redirect_handlers = {
        # Facebook
        'l.facebook.com': ('u',),
        'lm.facebook.com': ('u',),
        # LinkedIn
        'www.linkedin.com': ('url',),
        'linkedin.com': ('url',),
        # Twitter (t.co)
        't.co': (None,), # Twitter shortlinks don't use a param, the path is the encoded URL
        # Common marketing email parameters
        'click.email.example.com': ('url', 'link'),
    }

    # Handle Twitter t.co links (special case)
    if netloc == 't.co':
        # The path is the unique ID, we can't decode it without an API, so return original.
        # Alternatively, we could use a library like `pyshorteners` to try to expand it.
        print("ℹ️  Twitter t.co link detected. Consider using an URL expander API for full analysis.")
        return url

    # Handle other redirects with query parameters
    for service_domain, param_keys in redirect_handlers.items():
        if service_domain in netloc:
            for key in param_keys:
                if key in query_params:
                    clean_url = unquote(query_params[key][0])
                    print(f"✓ Extracted clean URL from {service_domain} redirect: {clean_url}")
                    return clean_url
            # If the domain matches but no parameter was found
            print(f"ℹ️  {service_domain} redirect detected, but no common parameter found.")

    return url

# ==================== MODULAR HEURISTIC CHECKS ====================
# Each check returns a (score, warning_message) tuple.

def check_ip_address(domain):
    if is_ip_address(domain):
        return 3, "Uses an IP address instead of a domain name. Legitimate companies rarely do this."
    return 0, ""

def check_tld(domain):
    tld = '.' + domain.split('.')[-1]
    if tld in HIGH_RISK_TLDS:
        return 2, f"Uses a high-risk top-level domain (TLD) '{tld}' often associated with scams."
    elif tld not in LOW_RISK_TLDS:
        return 1, f"Uses a less common TLD '{tld}'. Exercise caution."
    return 0, ""

def check_subdomain_count(domain):
    if domain.count('.') > 3:
        return 2, "Has an unusually high number of subdomains, a common trick to look legitimate."
    return 0, ""

def check_at_symbol(netloc):
    if '@' in netloc:
        return 3, "Contains an '@' symbol, which can be used to hide the real destination of a link."
    return 0, ""

def check_typosquatting(domain):
    # Extract the main part of the domain most likely to impersonate a brand
    domain_parts = domain.split('.')
    # Check the last two parts before the TLD
    candidates = domain_parts[-2:] if len(domain_parts) > 1 else domain_parts

    for candidate in candidates:
        for brand in KNOWN_BRANDS:
            similarity = difflib.SequenceMatcher(None, candidate, brand).ratio()
            # High similarity but not an exact match
            if similarity > 0.8 and candidate != brand:
                return 3, f"Domain '{candidate}' is suspiciously similar to known brand '{brand}' (similarity: {similarity:.1%})."
    return 0, ""

def check_url_encoding(url):
    if '%' in url:
        return 2, "Contains URL-encoded characters, which can be used to hide suspicious words."
    return 0, ""

def check_url_length(url):
    if len(url) > 100:
        return 1, "URL is unusually long, a common technique to hide the true destination."
    return 0, ""

def check_google_safe_browsing(url):
    """
    Checks a URL against Google's Safe Browsing API.
    Returns a score and warnings if the URL is known to be malicious.
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY or GOOGLE_SAFE_BROWSING_API_KEY == "YOUR_API_KEY_HERE":
        return 0, "[Info] Google Safe Browsing API key not configured."

    api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    payload = {
        "client": {
            "clientId": "bwscamscan",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {'key': GOOGLE_SAFE_BROWSING_API_KEY}
    try:
        response = requests.post(api_url, params=params, json=payload)
        response.raise_for_status()
        data = response.json()

        if data and 'matches' in data:
            threats = {match['threatType'] for match in data['matches']}
            threat_list = ', '.join(threats).lower().replace('_', ' ')
            return 10, f"❌ **CRITICAL WARNING:** This URL is flagged by Google Safe Browsing as: {threat_list}. DO NOT PROCEED."
    except requests.exceptions.RequestException as e:
        return 0, f"[Info] Could not check Safe Browsing database (Network Error)."
    except json.JSONDecodeError as e:
        return 0, f"[Info] Error decoding Safe Browsing API response."

    return 0, ""

# ==================== MAIN ANALYSIS FUNCTION ====================

def analyze_url_heuristics(url):
    """
    Analyzes a URL for common phishing scam patterns using a modular system of checks.
    Returns a dictionary with a 'score' and a list of 'warnings'.
    """
    result = {'score': 0, 'warnings': []}
    domain = get_domain(url)
    parsed_url = urlparse(url)

    # Define all heuristic check functions (excluding API check)
    heuristic_checks = [
        lambda: check_ip_address(domain),
        lambda: check_tld(domain),
        lambda: check_subdomain_count(domain),
        lambda: check_at_symbol(parsed_url.netloc),
        lambda: check_typosquatting(domain),
        lambda: check_url_encoding(url),
        lambda: check_url_length(url),
    ]

    # Run all heuristic checks
    for check in heuristic_checks:
        score, warning = check()
        if score > 0 and warning:  # Only add if there's a warning
            result['score'] += score
            result['warnings'].append(warning)

    return result


def remove_tracking_parameters(url):
    """
    Removes common tracking parameters (like fbclid, utm_*, gclid) from a URL.
    This is crucial for manual verification, as the original posted link won't have these.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # List of common tracking parameters to remove
    tracking_params = [
        'fbclid', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'gclid', 'gclsrc', 'dclid', 'msclkid', 'mc_cid', 'mc_eid', 'icid', 'vero_conv',
        'vero_id', 'yclid', '_openstat', 'hmb_campaign', 'hmb_medium', 'hmb_source'
    ]

    # Create a new query dictionary without tracking parameters
    clean_params = {}
    for param, value in query_params.items():
        if param.lower() not in tracking_params:
            # Keep the first value for each parameter
            clean_params[param] = value[0] if value else ''

    # Rebuild the URL with the cleaned query string
    new_query = urlencode(clean_params, doseq=False)

    # Reconstruct the URL
    if new_query:
        cleaned_url = parsed_url._replace(query=new_query).geturl()
    else:
        # If there are no query parameters left, remove the '?' entirely
        cleaned_url = parsed_url._replace(query=None).geturl()

    # If the URL is now exactly the same, or the only thing removed was tracking params, return it
    if cleaned_url != url:
        print(f"✓ Removed tracking parameters. Clean URL: {cleaned_url}")

    return cleaned_url
# ==================== MANUAL VERIFICATION ====================

def generate_manual_verification_links(suspicious_url, company_name):
    """
    Provides clear instructions for the user to manually verify a link
    on the official company's social media pages.
    """
    # FIRST AND MOST IMPORTANT: Clean the URL of tracking parameters
    clean_url_for_search = remove_tracking_parameters(suspicious_url)

    company_name_lower = company_name.strip().lower()
    social_media_url = COMPANY_PAGES.get(company_name_lower, None)

    result = {'message': "", 'social_media_url': None, 'clean_search_url': clean_url_for_search}

    if not social_media_url:
        result['message'] = f"""
🔍 **MANUAL VERIFICATION REQUIRED**

Since we don't have a direct link for {company_name}, please follow these steps:

1.  Go to Google and search for: "official {company_name} Facebook page"
2.  Make sure you are on their VERIFIED page (look for the blue checkmark ✓).
3.  Once on their page, find the **Search this Page** bar.
4.  PASTE this CLEANED link into the search bar and press Enter: 
    **{clean_url_for_search}**

🚨 **INTERPRETING RESULTS:**
   ✅ **IF FOUND:** The link is genuine and was posted by {company_name}.
   ❌ **IF NOT FOUND:** This is a strong indication of a SCAM. DO NOT proceed.
"""
        return result

    result['message'] = f"""🔍 **MANUAL VERIFICATION STEPS:**

1.  ➡️  CLICK HERE to go to the official {company_name.title()} Facebook page: {social_media_url}
    *(Look for the blue verification checkmark ✓ next to their name)*

2.  🔍 Once on their page, find the **"Search this Page"** bar (usually near the top).

3.  📋 PASTE this **CLEANED link** into the search bar and press Enter: 
    **{clean_url_for_search}**

    💡 *We've automatically removed Facebook tracking codes for accurate search results.*

4.  🧐 Wait for the results to load.

🚨 **HOW TO INTERPRET THE RESULTS:**

   ✅ **SAFE (Link appears):** If you see posts from {company_name} containing this cleaned link, it is genuine. You may proceed cautiously.

   ❌ **LIKELY SCAM (No results):** 
      - If the search returns **"No results found"** or **"No posts available for this content"**
      - This means {company_name} NEVER posted this link on their official page.
      - This is a STRONG INDICATOR of a phishing scam or fraudulent message.
      - 🛑 **DO NOT** click any links, download anything, or enter personal information.

   🤔 **UNSURE?** If you're not sure, contact {company_name} directly through their official website (found via Google, NOT this link) and ask them to verify the message.
"""
    result['social_media_url'] = social_media_url
    return result

# ==================== COMPREHENSIVE ANALYSIS ORCHESTRATOR ====================

def full_url_analysis(suspicious_url, company_name=""):
    """
    The main function to run a complete analysis on a URL.
    Handles redirects, API checks, heuristics, and provides verification steps.
    Returns a rich dictionary with all results for use in a GUI or CLI.
    """
    # Initialize the comprehensive results dictionary
    results = {
        'original_url': suspicious_url,
        'final_url': None,
        'safe_browsing': {'score': 0, 'warning': ""},
        'heuristics': {'score': 0, 'warnings': []},
        'total_score': 0,
        'risk_category': "Low",
        'verification_steps': {'message': "", 'social_media_url': None}
    }

    print(f"\n\033[1mOriginal URL: {suspicious_url}\033[0m")

    # 1. Clean Redirects
    clean_url = try_extract_clean_url(suspicious_url)
    url_to_analyze = clean_url
    results['final_url'] = url_to_analyze

    if url_to_analyze != suspicious_url:
        print(f"\033[1mAnalyzing extracted URL: {url_to_analyze}\033[0m")
    else:
        print(f"\033[1mAnalyzing URL: {url_to_analyze}\033[0m")

    # 2. High-confidence API Check (Do this first)
    sb_score, sb_warning = check_google_safe_browsing(url_to_analyze)
    results['safe_browsing']['score'] = sb_score
    results['safe_browsing']['warning'] = sb_warning
    if sb_score > 0:
        print(f"❌ {sb_warning}")

    # 3. Heuristic Analysis
    heuristic_analysis = analyze_url_heuristics(url_to_analyze)
    results['heuristics'] = heuristic_analysis # This is already a dict with 'score' and 'warnings'
    for warning in heuristic_analysis['warnings']:
        print(f"⚠️  {warning}")

    # 4. Calculate Total Score and Risk Category
    results['total_score'] = sb_score + heuristic_analysis['score']
    if results['total_score'] >= 8:
        results['risk_category'] = "CRITICAL"
    elif results['total_score'] >= 5:
        results['risk_category'] = "High"
    elif results['total_score'] >= 3:
        results['risk_category'] = "Medium"
    else:
        results['risk_category'] = "Low"

    print(f"\n🔍 Total Suspicion Score: {results['total_score']}/10+")
    print(f"📊 Risk Category: {results['risk_category']}")

    # 5. Provide Manual Verification Steps if a company name is provided
    if company_name:
        verification_info = generate_manual_verification_links(url_to_analyze, company_name)
        results['verification_steps'] = verification_info
        print(f"\n\033[1mGenerating Manual Verification Steps...\033[0m")
        print(verification_info['message'])

    return results

# ==================== TEST THE IMPROVED MODULE ====================

if __name__ == "__main__":
    # Test URLs
    test_urls = [
        ("https://l.facebook.com/l.php?u=https%3A%2F%2Fwww.0range-botwana.top%2Flogin", "orange"),
        ("http://142.93.56.78/.netlify/fnbb/secure-verify", "fnb"),
        ("https://www.google.com", "google") # A safe test
    ]

    for url, company in test_urls:
        print("\n" + "="*60)
        analysis_results = full_url_analysis(url, company)
        print("="*60)