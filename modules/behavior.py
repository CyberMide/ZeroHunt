# ZeroHunt - by Cybermide
# Module: Behavioral Fingerprinting

import requests
import time
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def scan(target, session, found_pages=[], verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] ZeroHunt - Running Behavioral Fingerprinting...")

    # ================================================
    # CHECK 1 - Technology Stack Fingerprinting
    # ================================================
    if verbose:
        print("  [*] Fingerprinting technology stack...")

    try:
        resp = session.get(target, timeout=8, verify=False)
        headers = resp.headers
        body = resp.text.lower()
        cookies = resp.cookies

        tech_stack = []
        security_issues = []

        # Server technology
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        if server:
            tech_stack.append(f"Server: {server}")
        if powered_by:
            tech_stack.append(f"Powered-By: {powered_by}")

        # Framework detection
        frameworks = {
            'Django': ['csrfmiddlewaretoken', 'django', '__admin__'],
            'Laravel': ['laravel_session', 'laravel', 'x-ratelimit'],
            'Ruby on Rails': ['_rails_session', 'x-rack', 'rack'],
            'Express.js': ['x-powered-by: express', 'express'],
            'ASP.NET': ['asp.net', 'viewstate', '__viewstate', 'x-aspnet'],
            'Spring': ['x-application-context', 'spring', 'jsessionid'],
            'Flask': ['werkzeug', 'flask'],
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', 'x-drupal'],
            'Joomla': ['joomla', '/components/com_'],
        }

        detected_frameworks = []
        for framework, signs in frameworks.items():
            for sign in signs:
                if (sign in body or
                    sign in str(headers).lower() or
                    sign in str([c.name for c in cookies]).lower()):
                    detected_frameworks.append(framework)
                    tech_stack.append(f"Framework: {framework}")
                    break

        # Cookie analysis
        for cookie in cookies:
            # Check for session fixation vulnerability indicators
            if any(word in cookie.name.lower() for word in ['session', 'sess', 'sid', 'auth']):
                if not cookie.secure:
                    security_issues.append({
                        'severity': 'HIGH',
                        'issue': f"Session cookie '{cookie.name}' missing Secure flag",
                        'evidence': f"Cookie: {cookie.name}={cookie.value[:20]}... | Secure=False",
                        'recommendation': 'Set Secure flag on all session cookies to prevent transmission over HTTP'
                    })
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    security_issues.append({
                        'severity': 'HIGH',
                        'issue': f"Session cookie '{cookie.name}' missing HttpOnly flag",
                        'evidence': f"Cookie: {cookie.name} | HttpOnly=False",
                        'recommendation': 'Set HttpOnly flag to prevent JavaScript access to session cookies'
                    })

                # Check for predictable session tokens
                value = cookie.value
                if value.isdigit():
                    security_issues.append({
                        'severity': 'CRITICAL',
                        'issue': f"Session token '{cookie.name}' is purely numeric - predictable",
                        'evidence': f"Cookie value is all digits: {value[:10]}...",
                        'recommendation': 'Use cryptographically random session tokens of at least 128 bits'
                    })
                elif len(value) < 16:
                    security_issues.append({
                        'severity': 'HIGH',
                        'issue': f"Session token '{cookie.name}' is too short ({len(value)} chars)",
                        'evidence': f"Cookie value length: {len(value)} characters",
                        'recommendation': 'Use session tokens of at least 32 characters'
                    })

        if tech_stack:
            results.append({
                'severity': 'INFO',
                'status': 'INFO',
                'title': 'Technology stack fingerprinted',
                'evidence': (
                    f"Target: {target}\n"
                    f"  Technologies detected:\n"
                    + '\n'.join([f"    - {t}" for t in tech_stack])
                ),
                'details': 'Technology stack identified - useful for targeted vulnerability research',
                'recommendation': 'Hide version information from response headers - remove X-Powered-By and Server headers'
            })
            if verbose:
                print(f"  [+] Tech stack: {', '.join(tech_stack)}")

        for issue in security_issues:
            results.append({
                'severity': issue['severity'],
                'status': 'VULNERABLE',
                'title': issue['issue'],
                'evidence': issue['evidence'],
                'details': issue['issue'],
                'recommendation': issue['recommendation']
            })
            if verbose:
                print(f"  [!] {issue['severity']}: {issue['issue']}")

    except Exception as e:
        pass

    # ================================================
    # CHECK 2 - Behavioral Consistency Testing
    # ================================================
    if verbose:
        print("  [*] Testing behavioral consistency...")

    try:
        # Get multiple responses and compare
        responses = []
        for i in range(3):
            resp = session.get(target, timeout=8, verify=False)
            responses.append({
                'status': resp.status_code,
                'size': len(resp.content),
                'hash': hashlib.md5(resp.content).hexdigest()
            })
            time.sleep(0.5)

        # Check if responses are consistent
        sizes = [r['size'] for r in responses]
        hashes = [r['hash'] for r in responses]

        if len(set(hashes)) > 1:
            size_variance = max(sizes) - min(sizes)
            if size_variance > 100:
                results.append({
                    'severity': 'LOW',
                    'status': 'ANOMALY',
                    'title': 'Inconsistent responses detected',
                    'evidence': (
                        f"Target: {target}\n"
                        f"  Response sizes across 3 requests: {sizes}\n"
                        f"  Size variance: {size_variance} bytes\n"
                        f"  Content hashes differ: {len(set(hashes))} unique responses\n"
                        f"  This may indicate dynamic content, load balancing or race conditions"
                    ),
                    'details': 'Server returns different content on repeated identical requests - may indicate race conditions or non-deterministic behavior',
                    'recommendation': 'Investigate source of response inconsistency - check for race conditions in session handling or data processing'
                })
                if verbose:
                    print(f"  [~] LOW: Inconsistent responses - size variance {size_variance} bytes")
            else:
                if verbose:
                    print("  [+] Responses are consistent")
        else:
            if verbose:
                print("  [+] Responses are consistent")

    except:
        pass

    # ================================================
    # CHECK 3 - Authentication State Behavior
    # ================================================
    if verbose:
        print("  [*] Testing authentication state behavior...")

    try:
        # Test with and without various auth headers
        auth_headers_tests = [
            {'Authorization': 'Bearer invalid_token_xyz'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin base64
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            {'Authorization': 'Bearer '},
            {'X-Auth-Token': 'invalid'},
            {'API-Key': 'invalid'},
        ]

        baseline_resp = session.get(target, timeout=8, verify=False)
        baseline_size = len(baseline_resp.content)
        baseline_status = baseline_resp.status_code

        for auth_headers in auth_headers_tests:
            try:
                resp = session.get(
                    target,
                    headers=auth_headers,
                    timeout=8,
                    verify=False
                )
                header_name = list(auth_headers.keys())[0]
                header_value = list(auth_headers.values())[0]

                # If invalid auth causes a different response it might mean
                # the server is processing the auth header unexpectedly
                size_diff = abs(len(resp.content) - baseline_size)
                if (resp.status_code != baseline_status or
                    (size_diff > 200 and baseline_size > 0)):
                    results.append({
                        'severity': 'MEDIUM',
                        'status': 'ANOMALY',
                        'title': f'Auth header causes behavioral change: {header_name}',
                        'evidence': (
                            f"Header sent: {header_name}: {header_value}\n"
                            f"  Baseline status: {baseline_status} | Got: {resp.status_code}\n"
                            f"  Baseline size: {baseline_size} bytes | Got: {len(resp.content)} bytes\n"
                            f"  Size difference: {size_diff} bytes"
                        ),
                        'details': f"Sending invalid '{header_name}' header caused a different server response - server may be processing auth headers in unexpected ways",
                        'recommendation': f"Ensure '{header_name}' header is properly validated - reject malformed auth tokens with 401 - do not process invalid tokens differently"
                    })
                    if verbose:
                        print(f"  [!] MEDIUM: {header_name} caused behavioral change")
            except:
                pass

    except:
        pass

    # ================================================
    # CHECK 4 - Cache Behavior Analysis
    # ================================================
    if verbose:
        print("  [*] Analyzing cache behavior...")

    try:
        cache_headers_tests = [
            {'Cache-Control': 'no-cache'},
            {'Cache-Control': 'max-age=0'},
            {'Pragma': 'no-cache'},
            {'If-Modified-Since': 'Thu, 01 Jan 1970 00:00:00 GMT'},
        ]

        baseline_resp = session.get(target, timeout=8, verify=False)

        for cache_headers in cache_headers_tests:
            try:
                resp = session.get(
                    target,
                    headers=cache_headers,
                    timeout=8,
                    verify=False
                )
                cache_control = resp.headers.get('Cache-Control', '')
                pragma = resp.headers.get('Pragma', '')

                # Check if sensitive pages are cached
                if 'public' in cache_control.lower():
                    results.append({
                        'severity': 'MEDIUM',
                        'status': 'VULNERABLE',
                        'title': 'Sensitive page may be publicly cached',
                        'evidence': (
                            f"Target: {target}\n"
                            f"  Cache-Control: {cache_control}\n"
                            f"  Pragma: {pragma}\n"
                            f"  Public caching detected - content may be stored in shared caches"
                        ),
                        'details': 'Page is marked as publicly cacheable - if sensitive data is present it may be stored and served from shared proxy caches',
                        'recommendation': "Set Cache-Control: no-store, private on all authenticated or sensitive pages"
                    })
                    if verbose:
                        print(f"  [!] MEDIUM: Page may be publicly cached")
                    break

            except:
                pass

    except:
        pass

    # ================================================
    # CHECK 5 - Error Behavior Mapping
    # ================================================
    if verbose:
        print("  [*] Mapping error behavior...")

    error_triggers = [
        (base + '/404-test-page-xyz', 404),
        (base + '/500-test?crash=true', 500),
        (base + '/index.php?id=\'', 500),
        (base + '/' + 'A' * 1000, 414),
    ]

    error_responses = {}
    for url, expected_code in error_triggers:
        try:
            resp = session.get(url, timeout=8, verify=False)
            error_responses[expected_code] = {
                'url': url,
                'actual_status': resp.status_code,
                'size': len(resp.content),
                'has_stack_trace': any(
                    sign in resp.text.lower()
                    for sign in ['traceback', 'stack trace', 'exception', 'at line']
                )
            }

            if error_responses[expected_code]['has_stack_trace']:
                results.append({
                    'severity': 'HIGH',
                    'status': 'VULNERABLE',
                    'title': f'Stack trace exposed in error response',
                    'evidence': (
                        f"Error URL: {url}\n"
                        f"  HTTP Status: {resp.status_code}\n"
                        f"  Stack trace indicators found in response\n"
                        f"  Preview: {resp.text[:300].strip()}"
                    ),
                    'details': 'Application exposes stack traces in error responses - reveals internal code structure and file paths to attackers',
                    'recommendation': 'Implement custom error pages - disable debug mode in production - log errors server-side only'
                })
                if verbose:
                    print(f"  [!] HIGH: Stack trace exposed at {url}")

        except:
            pass

    if not results:
        results.append({
            'severity': 'INFO',
            'status': 'NORMAL',
            'title': 'No behavioral anomalies detected',
            'evidence': f"Behavioral fingerprinting and consistency checks completed on {target}",
            'details': 'No significant behavioral anomalies detected during automated testing',
            'recommendation': 'Continue with manual behavioral testing - use Burp Suite for deeper analysis'
        })
        if verbose:
            print("  [+] No behavioral anomalies detected")

    return results