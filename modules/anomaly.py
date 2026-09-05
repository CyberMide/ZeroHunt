# ZeroHunt - by Cybermide
# Module: Anomaly-Based Response Detection

import requests
import time
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

def get_response_fingerprint(resp):
    """Create a fingerprint of a response for comparison"""
    return {
        'status': resp.status_code,
        'size': len(resp.content),
        'time': resp.elapsed.total_seconds(),
        'hash': hashlib.md5(resp.content).hexdigest(),
        'headers': dict(resp.headers),
        'redirect_count': len(resp.history),
    }

def get_baseline(target, session, samples=3):
    """Get baseline response fingerprints for normal requests"""
    baselines = []
    if not target:
        return baselines
    for _ in range(samples):
        try:
            resp = session.get(target, timeout=10, verify=False)
            baselines.append(get_response_fingerprint(resp))
            time.sleep(0.5)
        except:
            pass
    return baselines

def is_anomalous(resp, baselines, threshold=0.3):
    """
    Compare response against baseline.
    Returns True if response is anomalous.
    """
    if not baselines:
        return False

    fingerprint = get_response_fingerprint(resp)
    avg_size = sum(b['size'] for b in baselines) / len(baselines)
    avg_time = sum(b['time'] for b in baselines) / len(baselines)
    baseline_status = baselines[0]['status']
    baseline_hash = baselines[0]['hash']

    anomalies = []

    # Status code changed
    if fingerprint['status'] != baseline_status:
        anomalies.append(f"Status changed: {baseline_status} -> {fingerprint['status']}")

    # Size changed significantly
    if avg_size > 0:
        size_diff = abs(fingerprint['size'] - avg_size) / avg_size
        if size_diff > threshold:
            anomalies.append(f"Size anomaly: baseline={avg_size:.0f} bytes, got={fingerprint['size']} bytes ({size_diff*100:.1f}% change)")

    # Response time anomaly (possible blind injection or SSRF)
    if avg_time > 0 and fingerprint['time'] > avg_time * 3 and fingerprint['time'] > 2:
        anomalies.append(f"Time anomaly: baseline={avg_time:.2f}s, got={fingerprint['time']:.2f}s")

    # Content changed significantly
    if fingerprint['hash'] != baseline_hash:
        anomalies.append("Content hash changed from baseline")

    # New headers appeared
    baseline_header_keys = set(baselines[0]['headers'].keys())
    new_headers = set(fingerprint['headers'].keys()) - baseline_header_keys
    if new_headers:
        anomalies.append(f"New response headers: {', '.join(new_headers)}")

    return anomalies

def scan(target, session, found_pages=[], baselines_external=[], verbose=True):
    results = []

    if verbose:
        print("\n  [*] ZeroHunt - Running Anomaly Detection...")

    # Get baseline for this target
    if verbose:
        print("  [*] Building response baseline...")
    baselines = get_baseline(target, session)
    if not baselines:
        if verbose:
            print("  [!] Could not establish baseline - skipping anomaly detection")
        return results

    avg_baseline_time = sum(b['time'] for b in baselines) / len(baselines)
    avg_baseline_size = sum(b['size'] for b in baselines) / len(baselines)

    if verbose:
        print(f"  [+] Baseline established:")
        print(f"      Avg response time: {avg_baseline_time:.2f}s")
        print(f"      Avg response size: {avg_baseline_size:.0f} bytes")
        print(f"      Status code: {baselines[0]['status']}")

    # ================================================
    # CHECK 1 - HTTP Method Anomalies
    # ================================================
    if verbose:
        print("\n  [*] Testing HTTP method anomalies...")

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH',
               'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']

    for method in methods:
        try:
            resp = session.request(method, target, timeout=8, verify=False)
            anomalies = is_anomalous(resp, baselines)
            if anomalies and resp.status_code not in [405, 501]:
                results.append({
                    'severity': 'MEDIUM',
                    'status': 'ANOMALY',
                    'title': f'Unexpected response to {method} request',
                    'evidence': (
                        f"Method: {method} {target}\n"
                        f"  HTTP Status: {resp.status_code}\n"
                        f"  Response size: {len(resp.content)} bytes\n"
                        f"  Response time: {resp.elapsed.total_seconds():.2f}s\n"
                        f"  Anomalies detected:\n"
                        + '\n'.join([f"    - {a}" for a in anomalies])
                    ),
                    'details': f"HTTP {method} method produced an anomalous response compared to baseline GET request - may indicate unexpected server behavior or misconfiguration",
                    'recommendation': 'Investigate why this HTTP method produces a different response - disable unused HTTP methods on the server'
                })
                if verbose:
                    print(f"  [!] ANOMALY: {method} produced unexpected response")
        except:
            pass

    # ================================================
    # CHECK 2 - Header Injection Anomalies
    # ================================================
    if verbose:
        print("  [*] Testing header injection anomalies...")

    suspicious_headers = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Forwarded-For': 'localhost'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Original-URL': '/admin'},
        {'X-Rewrite-URL': '/admin'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Forwarded-Host': 'evil.com'},
        {'X-Host': 'evil.com'},
        {'X-Original-Host': 'evil.com'},
        {'Client-IP': '127.0.0.1'},
        {'True-Client-IP': '127.0.0.1'},
        {'Cluster-Client-IP': '127.0.0.1'},
        {'X-ProxyUser-Ip': '127.0.0.1'},
    ]

    for headers in suspicious_headers:
        try:
            resp = session.get(target, headers=headers, timeout=8, verify=False)
            anomalies = is_anomalous(resp, baselines)
            if anomalies:
                header_name = list(headers.keys())[0]
                header_value = list(headers.values())[0]
                results.append({
                    'severity': 'HIGH',
                    'status': 'ANOMALY',
                    'title': f'Header injection anomaly detected: {header_name}',
                    'evidence': (
                        f"Injected header: {header_name}: {header_value}\n"
                        f"  Target: {target}\n"
                        f"  HTTP Status: {resp.status_code}\n"
                        f"  Response size: {len(resp.content)} bytes\n"
                        f"  Anomalies detected:\n"
                        + '\n'.join([f"    - {a}" for a in anomalies])
                    ),
                    'details': f"Injecting '{header_name}: {header_value}' caused an anomalous response - server may be trusting this header for access control or routing decisions",
                    'recommendation': f"Do not trust '{header_name}' header for security decisions - validate all incoming headers - implement proper IP allowlisting at network level"
                })
                if verbose:
                    print(f"  [!] HIGH ANOMALY: Header {header_name} caused unexpected response")
        except:
            pass

    # ================================================
    # CHECK 3 - Response Time Anomalies (Blind Detection)
    # ================================================
    if verbose:
        print("  [*] Testing time-based anomalies...")

    time_payloads = [
        ('sleep(5)', 5),
        ('SLEEP(5)', 5),
        ("'; WAITFOR DELAY '0:0:5'--", 5),
        ('1; SELECT SLEEP(5)--', 5),
        (' OR SLEEP(5)--', 5),
        ('${Thread.sleep(5000)}', 5),
        ('#{T(java.lang.Thread).sleep(5000)}', 5),
    ]

    pages_to_test = [target] + found_pages[:3]

    for page in pages_to_test:
        parsed = urlparse(page)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param in params:
            for payload, expected_delay in time_payloads:
                try:
                    modified_params = params.copy()
                    modified_params[param] = [payload]
                    new_query = urlencode(modified_params, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))

                    start = time.time()
                    resp = session.get(new_url, timeout=15, verify=False)
                    elapsed = time.time() - start

                    if elapsed >= expected_delay * 0.8:
                        results.append({
                            'severity': 'CRITICAL',
                            'status': 'ANOMALY',
                            'title': f'Time-based blind injection anomaly detected',
                            'evidence': (
                                f"URL: {new_url}\n"
                                f"  Parameter: {param}\n"
                                f"  Payload: {payload}\n"
                                f"  Expected delay: {expected_delay}s\n"
                                f"  Actual response time: {elapsed:.2f}s\n"
                                f"  Baseline response time: {avg_baseline_time:.2f}s\n"
                                f"  Result: Server delayed significantly - possible blind injection"
                            ),
                            'details': f"Time-based payload caused server to delay {elapsed:.2f}s - this is a strong indicator of blind SQL injection or command injection that produces no visible output",
                            'recommendation': 'Immediately investigate this parameter for blind injection - use parameterised queries and input validation - conduct manual verification'
                        })
                        if verbose:
                            print(f"  [!] CRITICAL: Time-based anomaly in {page} param={param} ({elapsed:.2f}s delay)")
                except:
                    pass

    # ================================================
    # CHECK 4 - Content Type Anomalies
    # ================================================
    if verbose:
        print("  [*] Testing content type anomalies...")

    content_types = [
        'application/json',
        'application/xml',
        'text/xml',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain',
        'application/javascript',
    ]

    for ct in content_types:
        try:
            resp = session.get(
                target,
                headers={'Content-Type': ct, 'Accept': ct},
                timeout=8,
                verify=False
            )
            anomalies = is_anomalous(resp, baselines)
            if anomalies:
                results.append({
                    'severity': 'LOW',
                    'status': 'ANOMALY',
                    'title': f'Content-Type anomaly with: {ct}',
                    'evidence': (
                        f"Request Content-Type: {ct}\n"
                        f"  Target: {target}\n"
                        f"  HTTP Status: {resp.status_code}\n"
                        f"  Response size: {len(resp.content)} bytes\n"
                        f"  Anomalies:\n"
                        + '\n'.join([f"    - {a}" for a in anomalies])
                    ),
                    'details': f"Sending Content-Type: {ct} produced an anomalous response - server may handle different content types in unexpected ways",
                    'recommendation': 'Ensure server validates and sanitises input regardless of Content-Type header - implement strict content type validation'
                })
                if verbose:
                    print(f"  [!] LOW ANOMALY: Content-Type {ct} caused unexpected response")
        except:
            pass

    if not results:
        results.append({
            'severity': 'INFO',
            'status': 'NORMAL',
            'title': 'No response anomalies detected',
            'evidence': f"All requests produced responses consistent with baseline\n  Baseline avg time: {avg_baseline_time:.2f}s\n  Baseline avg size: {avg_baseline_size:.0f} bytes",
            'details': 'No anomalous responses detected during automated testing',
            'recommendation': 'Continue with manual testing - automated anomaly detection has coverage limitations'
        })
        if verbose:
            print("  [+] No anomalies detected")

    return results