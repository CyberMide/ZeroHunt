# ZeroHunt - by Cybermide
# Module: Business Logic Flaw Detection

import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

def get_forms(url, session):
    """Extract all forms from a page"""
    forms = []
    try:
        resp = session.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', url)),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            for inp in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                })
            forms.append(form_data)
    except:
        pass
    return forms

def scan(target, session, found_pages=[], verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] ZeroHunt - Running Business Logic Flaw Detection...")

    pages_to_test = [target] + found_pages[:5]

    # ================================================
    # CHECK 1 - Negative Value Attacks
    # ================================================
    if verbose:
        print("  [*] Testing negative value attacks...")

    negative_payloads = ['-1', '-100', '-0.01', '-99999', '0', '0.00']

    for page in pages_to_test:
        parsed = urlparse(page)
        params = parse_qs(parsed.query)

        for param in params:
            param_lower = param.lower()
            if any(word in param_lower for word in [
                'price', 'amount', 'quantity', 'qty', 'count',
                'total', 'cost', 'value', 'num', 'number',
                'credit', 'debit', 'balance', 'fee', 'rate'
            ]):
                for payload in negative_payloads:
                    try:
                        modified = params.copy()
                        modified[param] = [payload]
                        new_query = urlencode(modified, doseq=True)
                        new_url = urlunparse(parsed._replace(query=new_query))

                        resp = session.get(new_url, timeout=8, verify=False)

                        if resp.status_code == 200:
                            body = resp.text.lower()
                            success_signs = [
                                'success', 'confirmed', 'approved',
                                'processed', 'complete', 'thank you',
                                'order placed', 'payment accepted'
                            ]
                            if any(sign in body for sign in success_signs):
                                results.append({
                                    'severity': 'CRITICAL',
                                    'status': 'VULNERABLE',
                                    'title': f'Negative value accepted in parameter: {param}',
                                    'evidence': (
                                        f"URL: {new_url}\n"
                                        f"  Parameter: {param}\n"
                                        f"  Payload: {payload}\n"
                                        f"  HTTP Status: {resp.status_code}\n"
                                        f"  Success indicators found in response\n"
                                        f"  Result: Application accepted negative value without rejection"
                                    ),
                                    'details': f"Parameter '{param}' accepted negative value '{payload}' and returned a success response - attacker may be able to get refunds, credits or free items",
                                    'recommendation': 'Implement server-side validation for all numeric inputs - reject negative or zero values for quantity and price fields'
                                })
                                if verbose:
                                    print(f"  [!] CRITICAL: Negative value accepted in {param}={payload}")
                    except:
                        pass

    # ================================================
    # CHECK 2 - Workflow Step Bypass
    # ================================================
    if verbose:
        print("  [*] Testing workflow step bypass...")

    workflow_paths = [
        # E-commerce checkout flows
        ('/checkout', '/checkout/payment', '/checkout/confirm', '/checkout/complete'),
        ('/cart', '/shipping', '/payment', '/order-complete'),
        ('/step1', '/step2', '/step3', '/step4'),
        ('/register', '/verify', '/complete'),
        ('/signup', '/confirm', '/dashboard'),
        # Password reset flows
        ('/forgot-password', '/reset-password', '/password-changed'),
        # Onboarding flows
        ('/onboarding/step1', '/onboarding/step2', '/onboarding/step3'),
    ]

    for flow in workflow_paths:
        if len(flow) < 2:
            continue
        # Try to skip to the last step directly
        final_step = base + flow[-1]
        try:
            resp = session.get(final_step, timeout=8, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                # Check if we actually reached the final step
                success_signs = [
                    'complete', 'success', 'confirmed', 'order',
                    'thank you', 'welcome', 'dashboard', 'done'
                ]
                if any(sign in body for sign in success_signs):
                    results.append({
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': f'Workflow step bypass possible: {flow[-1]}',
                        'evidence': (
                            f"Final step URL: {final_step}\n"
                            f"  HTTP Status: {resp.status_code}\n"
                            f"  Success indicators found without completing prior steps\n"
                            f"  Expected flow: {' -> '.join(flow)}\n"
                            f"  Result: Final step accessible directly"
                        ),
                        'details': f"Final workflow step '{flow[-1]}' is accessible without completing prerequisite steps - attacker can skip payment, verification or other required steps",
                        'recommendation': 'Implement server-side workflow state tracking - verify all prerequisite steps are completed before allowing access to later steps'
                    })
                    if verbose:
                        print(f"  [!] HIGH: Workflow bypass possible at {final_step}")
        except:
            pass

    # ================================================
    # CHECK 3 - Price and Discount Manipulation
    # ================================================
    if verbose:
        print("  [*] Testing price manipulation...")

    for page in pages_to_test:
        parsed = urlparse(page)
        params = parse_qs(parsed.query)

        price_params = [
            p for p in params
            if any(word in p.lower() for word in [
                'price', 'cost', 'amount', 'total',
                'discount', 'coupon', 'promo', 'fee'
            ])
        ]

        for param in price_params:
            manipulation_payloads = ['0', '0.01', '-1', '0.001', '1']
            for payload in manipulation_payloads:
                try:
                    modified = params.copy()
                    modified[param] = [payload]
                    new_query = urlencode(modified, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))

                    resp = session.get(new_url, timeout=8, verify=False)
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        if any(sign in body for sign in ['success', 'confirmed', 'order']):
                            results.append({
                                'severity': 'CRITICAL',
                                'status': 'VULNERABLE',
                                'title': f'Price manipulation accepted: {param}={payload}',
                                'evidence': (
                                    f"URL: {new_url}\n"
                                    f"  Parameter: {param}\n"
                                    f"  Manipulated value: {payload}\n"
                                    f"  HTTP Status: {resp.status_code}\n"
                                    f"  Success response returned"
                                ),
                                'details': f"Price parameter '{param}' was successfully manipulated to '{payload}' - attacker can modify prices client-side to purchase items for free or at reduced cost",
                                'recommendation': 'Never trust client-supplied price or discount values - calculate all prices server-side from a trusted database - validate against expected values'
                            })
                            if verbose:
                                print(f"  [!] CRITICAL: Price manipulation in {param}={payload}")
                except:
                    pass

    # ================================================
    # CHECK 4 - Token Reuse Detection
    # ================================================
    if verbose:
        print("  [*] Testing token reuse vulnerabilities...")

    token_paths = [
        '/reset-password', '/verify-email', '/confirm',
        '/activate', '/unsubscribe', '/magic-link'
    ]

    for path in token_paths:
        url = base + path
        try:
            # Try accessing with a fake token
            test_tokens = [
                '?token=aaaa1111bbbb2222cccc3333dddd4444',
                '?token=00000000000000000000000000000000',
                '?token=1',
                '?token=admin',
                '?token=test',
            ]
            for token_param in test_tokens:
                resp = session.get(url + token_param, timeout=8, verify=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(sign in body for sign in [
                        'password', 'reset', 'confirm', 'verified',
                        'success', 'token valid', 'link valid'
                    ]):
                        results.append({
                            'severity': 'HIGH',
                            'status': 'VULNERABLE',
                            'title': f'Weak token validation at: {path}',
                            'evidence': (
                                f"URL: {url + token_param}\n"
                                f"  Token tested: {token_param}\n"
                                f"  HTTP Status: {resp.status_code}\n"
                                f"  Sensitive content returned with invalid token"
                            ),
                            'details': f"Endpoint '{path}' returned sensitive content with a potentially invalid or guessable token - token validation may be weak or missing",
                            'recommendation': 'Use cryptographically random tokens of at least 256 bits - implement single-use tokens - add expiry times - validate server-side'
                        })
                        if verbose:
                            print(f"  [!] HIGH: Weak token validation at {url}")
                        break
        except:
            pass

    # ================================================
    # CHECK 5 - Race Condition Detection
    # ================================================
    if verbose:
        print("  [*] Testing for race condition indicators...")

    import threading

    race_results = []
    race_lock = threading.Lock()

    def make_request(url, result_list):
        try:
            resp = session.get(url, timeout=8, verify=False)
            with race_lock:
                result_list.append({
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'time': resp.elapsed.total_seconds()
                })
        except:
            pass

    # Send 5 simultaneous requests
    threads = []
    simultaneous_results = []
    for _ in range(5):
        t = threading.Thread(
            target=make_request,
            args=(target, simultaneous_results)
        )
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if simultaneous_results:
        sizes = [r['size'] for r in simultaneous_results]
        statuses = [r['status'] for r in simultaneous_results]

        if len(set(sizes)) > 2 or len(set(statuses)) > 1:
            results.append({
                'severity': 'MEDIUM',
                'status': 'ANOMALY',
                'title': 'Potential race condition detected',
                'evidence': (
                    f"Target: {target}\n"
                    f"  5 simultaneous requests sent\n"
                    f"  Response sizes: {sizes}\n"
                    f"  Response statuses: {statuses}\n"
                    f"  Inconsistent responses suggest race condition vulnerability"
                ),
                'details': 'Simultaneous requests produced inconsistent responses - may indicate race conditions in session handling, inventory management or financial transactions',
                'recommendation': 'Implement proper locking mechanisms - use database transactions - add idempotency keys for financial operations'
            })
            if verbose:
                print(f"  [!] MEDIUM: Potential race condition detected")
        else:
            if verbose:
                print("  [+] No race condition indicators found")

    if not results:
        results.append({
            'severity': 'INFO',
            'status': 'NORMAL',
            'title': 'No business logic flaws detected',
            'evidence': f"Business logic checks completed on {len(pages_to_test)} pages",
            'details': 'No obvious business logic flaws detected - manual testing recommended for complete coverage',
            'recommendation': 'Conduct manual business logic testing - map all application workflows and test each transition - use Burp Suite for deeper analysis'
        })
        if verbose:
            print("  [+] No business logic flaws detected")

    return results