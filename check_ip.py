"""
IP Checker 2025
Tool for analyzing IP addresses and domains
"""
import argparse
import json
import socket
import sys
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import json
import requests
import ipaddress
from urllib.parse import urlparse

# Configuration
cache_duration = timedelta(hours=24)
cache_folder = Path.home() / ".ip_checker_cache_2025"
ip_api_url = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

def create_cache_folder():
    cache_folder.mkdir(parents=True, exist_ok=True)

def create_cache_key(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

def get_cached_data(ip):
    create_cache_folder()
    cache_key = create_cache_key(ip)
    cache_file = cache_folder / f"{cache_key}.json"

    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            
            # Parse stored timestamp back to datetime object
            timestamp_str = cached_data.get('timestamp')
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str)
                if datetime.now() - timestamp < cache_duration:
                    print(f"Using cached data for {ip}")
                    return cached_data
        except Exception as e:
            # If cache is corrupted, ignore it
            pass
    return None

def save_to_cache(ip, data):
    create_cache_folder()
    cache_key = create_cache_key(ip)
    cache_file = cache_folder / f"{cache_key}.json"

    cache_data = {
        'timestamp': datetime.now().isoformat(),
        'data': data
    }

    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save cache: {e}")

def get_ip_geolocation_data(ip):
    cached = get_cached_data(ip)
    if cached:
        return cached['data'].get('geolocation')

    try:
        response = requests.get(ip_api_url.format(ip=ip), timeout=15)
        response.raise_for_status()
        result = response.json()

        # Save to cache
        cached_data = get_cached_data(ip) or {'data': {}}
        cached_data['data']['geolocation'] = result
        save_to_cache(ip, cached_data['data'])

        return result
    except requests.RequestException as e:
        print(f"Geolocation API error: {e}")
        return None
    except json.JSONDecodeError:
        print("Geolocation API returned invalid JSON")
        return None

def get_tor_exit_nodes():
    """Fetch the list of Tor exit nodes from the official Tor Project check list."""
    cache_key = "tor_exit_nodes_list"
    cached = get_cached_data(cache_key)
    
    if cached:
        return set(cached['data'])

    try:
        url = "https://check.torproject.org/torbulkexitlist"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        nodes = set(response.text.strip().splitlines())
        save_to_cache(cache_key, list(nodes))
        return nodes
    except Exception as e:
        print(f"Warning: Could not fetch Tor exit nodes: {e}")
        return set()

def get_threat_intel_data(ip):
    # Import necessary module for env vars
    import os
    
    cached = get_cached_data(ip)
    if cached and cached['data'].get('threat_intel'):
        return cached['data']['threat_intel']

    # 1. Check if IP is a Tor Exit Node (Public Source - No Key needed)
    tor_nodes = get_tor_exit_nodes()
    is_tor = ip in tor_nodes

    # 2. VirusTotal (Requires API Key)
    vt_key = os.environ.get('VIRUSTOTAL_API_KEY')
    vt_result = "N/A (No API Key)"
    vt_score = None
    
    if vt_key:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": vt_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                vt_score = f"{stats['malicious']}/{stats['malicious'] + stats['harmless']}"
                vt_result = "Malicious" if stats['malicious'] > 0 else "Clean"
        except Exception as e:
            vt_result = f"Error: {e}"

    # Construct the result object (No Fake Data)
    result = {
        "ipAddress": ip,
        "isTor": is_tor,
        "virusTotalAnalysis": vt_result,
        "virusTotalScore": vt_score,
        "abuseConfidenceScore": "N/A (Add ABUSEIPDB_API_KEY env var)",
        "note": "Real-time checks performed. No random guesses."
    }

    cached_data = get_cached_data(ip) or {'data': {}}
    cached_data['data']['threat_intel'] = result
    save_to_cache(ip, cached_data['data'])

    return result

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_domain_to_ip(domain):
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ipv4_addrs = set()
        ipv6_addrs = set()

        for info in addr_info:
            addr = info[4][0]
            if info[0] == socket.AF_INET:
                ipv4_addrs.add(addr)
            elif info[0] == socket.AF_INET6:
                ipv6_addrs.add(addr)

        ipv4_list = list(ipv4_addrs)
        ipv6_list = list(ipv6_addrs)

        if ipv4_list:
            return ipv4_list[0], ipv6_list
        elif ipv6_list:
            return ipv6_list[0], []
        else:
            raise socket.gaierror("No IP address found for domain")
    except socket.gaierror as e:
        raise socket.gaierror(f"Could not resolve domain: {e}")

def reverse_dns_lookup(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "No PTR record found"

def get_ip_reputation_score(ip):
    score = 50  # Base score

    try:
        ip_obj = ipaddress.ip_address(ip)

        # Adjust score based on IP type
        if ip_obj.is_private:
            score += 20  # Private IPs are generally safer
        elif ip_obj.is_loopback:
            score += 15  # Loopback IPs are safe
        elif ip_obj.is_multicast:
            score -= 10  # Multicast IPs are unusual
        elif ip_obj.is_reserved:
            score -= 15  # Reserved IPs are suspicious
        else:
            score += 0  # Public IPs are neutral

        # Adjust based on heuristics
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            score += 10  # Internal network IPs
        elif ip.startswith("8.8.") or ip.startswith("8."):
            score += 5   # Common DNS providers

    except:
        score = 0  # Invalid IP

    # Ensure score is between 0 and 100
    return max(0, min(100, score))

def get_asn_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=as,asname,message", timeout=15)
        response.raise_for_status()
        data = response.json()

        if data.get('status') == 'success':
            return {
                'asn': data.get('as'),
                'asname': data.get('asname'),
                'org': data.get('org')
            }
        return None
    except:
        return None

def analyze_ip(ip, output_format='text'):
    analysis_result = {
        'ip_address': ip,
        'analysis_timestamp': datetime.now().isoformat(),
        'geolocation': None,
        'threat_intel': None,
        'network_info': {},
        'additional_analysis': {}
    }

    if not is_valid_ip(ip):
        error_msg = f"Invalid IP address: {ip}"
        if output_format == 'json':
            analysis_result['error'] = error_msg
            print(json.dumps(analysis_result, indent=2))
        else:
            print(f"ERROR: {error_msg}")
        return analysis_result

    # Get data for analysis
    geo_data = get_ip_geolocation_data(ip)
    threat_data = get_threat_intel_data(ip)
    reverse_dns = reverse_dns_lookup(ip)
    asn_info = get_asn_info(ip)
    reputation_score = get_ip_reputation_score(ip)

    # Set data in result
    analysis_result['geolocation'] = geo_data
    analysis_result['threat_intel'] = threat_data
    analysis_result['network_info']['reverse_dns'] = reverse_dns
    analysis_result['network_info']['asn_info'] = asn_info
    analysis_result['additional_analysis']['reputation_score'] = reputation_score

    # Determine IP type and version
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private:
        ip_type = 'Private IP Address'
    elif ip_obj.is_loopback:
        ip_type = 'Loopback IP Address'
    elif ip_obj.is_multicast:
        ip_type = 'Multicast IP Address'
    elif ip_obj.is_reserved:
        ip_type = 'Reserved IP Address'
    else:
        ip_type = 'Public IP Address'

    analysis_result['additional_analysis']['ip_type'] = ip_type
    analysis_result['additional_analysis']['ip_version'] = f"IPv{ip_obj.version}"
    analysis_result['additional_analysis']['is_global'] = ip_obj.is_global if hasattr(ip_obj, 'is_global') else not ip_obj.is_private

    # Output the results
    if output_format == 'json':
        print(json.dumps(analysis_result, indent=2, default=str))
        return analysis_result
    else:
        print(f"COMPREHENSIVE IP ANALYSIS - {analysis_result['analysis_timestamp']}")
        print(f"IP Address: {analysis_result['ip_address']}")
        print(f"Analysis Time: {analysis_result['analysis_timestamp']}")

        print(f"\n GEOLOCATION DATA:")
        geo = analysis_result['geolocation']
        if geo and geo.get('status') == 'success':
            print(f"  Country: {geo.get('country', 'N/A')} ({geo.get('countryCode', 'N/A')})")
            print(f"  Region: {geo.get('regionName', 'N/A')}")
            print(f"  City: {geo.get('city', 'N/A')}")
            print(f"  ZIP Code: {geo.get('zip', 'N/A')}")
            print(f"  Coordinates: {geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}")
            print(f"  Timezone: {geo.get('timezone', 'N/A')}")
            print(f"  ISP: {geo.get('isp', 'N/A')}")
            print(f"  Organization: {geo.get('org', 'N/A')}")
            print(f"  ASN: {geo.get('as', 'N/A')}")
        else:
            print("  Failed to retrieve geolocation data")

        print(f"\n THREAT INTELLIGENCE:")
        threat = analysis_result['threat_intel']
        if threat:
            print(f"  Is Tor Exit Node: {threat.get('isTor', 'N/A')}")
            print(f"  VirusTotal Analysis: {threat.get('virusTotalAnalysis', 'N/A')}")
            if threat.get('virusTotalScore'):
                print(f"  VirusTotal Score: {threat.get('virusTotalScore')}")
            print(f"  AbuseIPDB Score: {threat.get('abuseConfidenceScore', 'N/A')}")
            print(f"  Note: {threat.get('note', '')}")
        else:
            print("  Failed to retrieve threat intelligence data")

        print(f"\n NETWORK INFORMATION:")
        net_info = analysis_result['network_info']
        print(f"  Reverse DNS: {net_info['reverse_dns']}")
        asn = net_info.get('asn_info')
        if asn:
            print(f"  ASN: {asn.get('asn', 'N/A')}")
            print(f"  AS Name: {asn.get('asname', 'N/A')}")
            print(f"  Organization: {asn.get('org', 'N/A')}")

        print(f"\n ADDITIONAL ANALYSIS:")
        additional = analysis_result['additional_analysis']
        print(f"  IP Type: {additional['ip_type']}")
        print(f"  IP Version: {additional['ip_version']}")
        print(f"  Is Global: {additional['is_global']}")
        print(f"  Reputation Score: {additional['reputation_score']}/100")

        print(f"ANALYSIS COMPLETE")

        return analysis_result

def main():
    parser = argparse.ArgumentParser(
        description="IP Checker 2025 - Tool for analyzing IP addresses and domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python check_ip_2025.py 8.8.8.8
  python check_ip_2025.py google.com
  python check_ip_2025.py 8.8.8.8 --format json
  python check_ip_2025.py 8.8.8.8 --format text --no-cache
        """
    )
    parser.add_argument('target', help='IP address or domain to analyze')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--no-cache', action='store_true',
                        help='Skip cache and fetch fresh data')

    args = parser.parse_args()

    # Handle cache disabling
    if args.no_cache:
        global get_cached_data
        original_get_cached_data = get_cached_data
        get_cached_data = lambda ip: None  # Always return None to skip cache

    try:
        target = args.target.strip()

        if not target:
            print("Error: Target cannot be empty", file=sys.stderr)
            parser.print_help()
            sys.exit(1)

        # Check if target is a URL, extract domain if it is
        if target.startswith(('http://', 'https://')):
            parsed_url = urlparse(target)
            domain = parsed_url.netloc
            if not domain:
                print(f"Error: Could not extract domain from URL: {target}", file=sys.stderr)
                sys.exit(1)
        else:
            domain = target

        if is_valid_ip(domain):
            ip_addr = domain
        else:
            # It's a domain, resolve it to IP
            ip_addr, ipv6_addrs = resolve_domain_to_ip(domain)

            if ipv6_addrs and args.format == 'text':
                print(f"IPv6 addresses found: {', '.join(ipv6_addrs[:3])}")

            if args.format == 'text':
                print(f"Target: {target}")
                print(f"Domain: {domain}")
                print(f"Resolved IP Address: {ip_addr}")

        analyze_ip(ip_addr, output_format=args.format)

    except socket.gaierror as e:
        print(f"Error resolving domain: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Restore original cache function if we modified it
        if args.no_cache:
            get_cached_data = original_get_cached_data

if __name__ == "__main__":
    main()