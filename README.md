# MCP Scanner

> **This is a fork adapted from a [Knostic Research Project](https://github.com/knostic/MCP-Scanner)**  
> Research tool for discovering and analyzing Model Context Protocol (MCP) servers using the Shodan search engine.


## ✨ **Features**

- **Comprehensive Discovery**: Uses 100+ Shodan search filters to find MCP servers
- **Multi-Transport Support**: Tests both HTTP and Server-Sent Events (SSE) transports
- **Protocol Verification**: Validates actual MCP protocol compliance
- **Tool Enumeration**: Discovers available tools and capabilities
- **Detailed Reporting**: Generates JSON, CSV, and summary reports
- **Rate Limiting**: Built-in concurrent request limiting
- **Cross-Platform**: Works on Windows, macOS, and Linux

## 🚀 **Quick Start**

### Prerequisites

- Python 3.7+
- Shodan API key ([Get one here](https://shodan.io/))

### Installation

```bash
# Clone the repository
git clone https://github.com/knostic/MCP-Scanner.git
cd MCP-Scanner

# Install dependencies
pip install shodan requests aiohttp

# Or use requirements.txt if provided
pip install -r requirements.txt
```

### Basic Usage

```bash
# Run the scanner
python mcp_scanner.py --api-key YOUR_SHODAN_API_KEY

# With custom options
python mcp_scanner.py --api-key YOUR_API_KEY --max-results 100 --max-concurrent 15 --output my_results.json

# Inspect specific servers
python mcp_func_checker.py --servers server1.com:8000,server2.com:3000
```

## 📊 **Output**

The scanner generates multiple output files:
- `mcp_scan_results_[timestamp]/verified_servers.json` - Detailed server information
- `mcp_scan_results_[timestamp]/verified_servers.csv` - CSV format for analysis
- `mcp_scan_results_[timestamp]/scan_summary.txt` - Human-readable summary
- `mcp_discovery_[timestamp].log` - Detailed execution logs

## 🛠️ **Command Line Options**

### mcp_scanner.py
```
--api-key          Shodan API key (required)
--max-results      Maximum results per Shodan filter (default: 50)
--max-concurrent   Maximum concurrent connections (default: 10)
--output           Custom output filename prefix
```

### mcp_func_checker.py
```
--servers          Comma-separated list of servers to inspect
--file             File containing server list (one per line)
--timeout          Connection timeout in seconds (default: 10)
--output           Output filename for results
```

## 🔧 **Advanced Usage**

### Custom Shodan Filters

The scanner uses 100+ predefined Shodan filters. You can modify the `shodan_filters` list in `mcp_scanner.py` to add custom search patterns.

### Analyzing Results

```python
import json

# Load scan results
with open('mcp_scan_results_timestamp/verified_servers.json', 'r') as f:
    servers = json.load(f)

# Analyze discovered tools
for server in servers:
    if 'tools' in server:
        print(f"Server: {server['url']}")
        print(f"Tools: {server['tools']}")
```

## 🔒 **Example Research Applications**

- **Exposed MCP Server Discovery**: Find unintentionally public MCP servers
- **Configuration Analysis**: Identify misconfigurations and security issues
- **Tool Enumeration**: Catalog available tools and capabilities
- **Protocol Compliance Testing**: Verify proper MCP implementation
- **Attack Surface Mapping**: Understand MCP deployment patterns
