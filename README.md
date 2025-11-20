# IP Checker 2025

Advanced IP address and domain analysis tool with modern security intelligence and comprehensive network data.

## Features

- **IP Geolocation**: Detailed location data (country, city, coordinates, ISP, timezone)
- **Security Intelligence**: Trust score, VPN/proxy/TOR detection, abuse reporting
- **ASN Information**: Autonomous System Number and organization details
- **IP Reputation Scoring**: Comprehensive reputation analysis
- **Dual Stack Support**: Full IPv4 and IPv6 compatibility
- **Reverse DNS Lookup**: Hostname resolution from IP address
- **Enhanced Output**: Both text and JSON formats with detailed analysis
- **Smart Caching**: 24-hour intelligent caching for performance
- **Modern CLI**: Command-line interface with intuitive options
- **Network Intelligence**: Comprehensive network analysis and classification
- **Privacy Focused**: Local caching and minimal data sharing

## Installation

Make sure you have Python 3.8+ installed on your computer, then:

```bash
pip install requests
```

## How to Use

### Basic Usage
```bash
python check_ip_2025.py 8.8.8.8
python check_ip_2025.py google.com
```

### Advanced Usage
```bash
# JSON output format
python check_ip_2025.py 8.8.8.8 --format json

# Skip cache for fresh data
python check_ip_2025.py 8.8.8.8 --no-cache

# Custom timeout
python check_ip_2025.py 8.8.8.8 --timeout 30
```

### Command Line Options
- `target`: IP address or domain to analyze
- `--format, -f`: Output format (text/json) [default: text]
- `--no-cache`: Skip cache and fetch fresh data
- `--timeout`: Request timeout in seconds [default: 15]

## Example

### Text Output
```
python check_ip_2025.py google.com
```

### JSON Output
```
python check_ip_2025.py 8.8.8.8 --format json
```

## Output Information

You'll get comprehensive analysis including:
- **Geolocation**: Country, region, city, coordinates, timezone, ISP
- **Security**: Trust score, VPN/proxy/TOR detection, abuse reports
- **ASN Details**: Autonomous System Number and organization
- **Network Info**: Reverse DNS, IP type, version, reputation
- **Analysis**: Classification and risk assessment
- **Timestamp**: When the analysis was performed

## Configuration

- **API Integration**: Supports AbuseIPDB API with environment variable `ABUSEIPDB_API_KEY`
- **Caching**: Data cached in `~/.ip_checker_cache_2025/` for 24 hours
- **Timeout**: Default request timeout is 15 seconds, configurable via CLI

## 2025 Enhancements

- **Enhanced Security**: Advanced threat intelligence and reputation scoring
- **Global Coverage**: Improved geolocation accuracy with multiple data sources
- **Enterprise Ready**: Structured JSON output for automation and integration
- **Performance Optimized**: Smart caching and faster response times
- **Privacy First**: Local-first approach with minimal data sharing
- **Modern Architecture**: Type hints, error handling, and maintainable code

## Privacy

- IP data is cached locally for 24 hours to minimize API calls
- No personal data is collected or transmitted
- Supports offline operation with cached data
- Configurable caching and privacy controls

## Notes

- Data is cached locally for 24 hours to optimize performance
- JSON output format supports programmatic integration
- IPv6 support with full analysis capabilities
- Enhanced security checks with modern threat intelligence