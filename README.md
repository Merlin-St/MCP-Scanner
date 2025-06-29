# MCP Scanner

> **A Knostic Research Project**  
> Advanced security research tool for discovering and analyzing Model Context Protocol (MCP) servers using the Shodan search engine.

*Part of Knostic's ongoing research into AI infrastructure security and data governance.*

## ⚠️ **Important Disclaimer**

**This tool is designed for legitimate security research, authorized penetration testing, and educational purposes only.** 

- Only scan systems you own or have explicit written permission to test
- Respect rate limits and terms of service for all APIs used
- Follow all applicable local, state, and federal laws
- Be responsible and ethical in your security research

*Knostic is committed to advancing AI security through responsible research practices.*

## 🔍 **What is MCP?**

The Model Context Protocol (MCP) is an open protocol that enables secure connections between host applications (like Claude Desktop) and external data sources and tools. As enterprises increasingly adopt AI infrastructure, understanding the security posture of MCP deployments becomes critical for:

- **Data Governance**: Ensuring sensitive information isn't exposed through misconfigured MCP servers
- **Attack Surface Management**: Identifying publicly accessible AI infrastructure components  
- **Compliance**: Meeting regulatory requirements for AI system security
- **Risk Assessment**: Understanding the broader AI ecosystem your organization interacts with

This scanner helps security professionals identify publicly exposed MCP servers for research and assessment purposes.

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

## 🔒 **Security Research Applications**

- **Exposed MCP Server Discovery**: Find unintentionally public MCP servers
- **Configuration Analysis**: Identify misconfigurations and security issues
- **Tool Enumeration**: Catalog available tools and capabilities
- **Protocol Compliance Testing**: Verify proper MCP implementation
- **Attack Surface Mapping**: Understand MCP deployment patterns

## 🤝 **Contributing**

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- [Anthropic](https://anthropic.com) for the Model Context Protocol specification
- [Shodan](https://shodan.io) for their excellent search engine API
- The security research community for responsible disclosure practices

## 📚 **Learn More**

### About MCP
- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [MCP GitHub Repository](https://github.com/modelcontextprotocol)

### About Knostic
- [Knostic AI Security Platform](https://www.knostic.ai/)
- [LLM Oversharing Research](https://www.knostic.ai/)
- [AI Data Governance Solutions](https://www.knostic.ai/)
- [Responsible Security Research Guidelines](https://github.com/microsoft/responsible-ai-guidelines)

---

**Developed by [Knostic](https://www.knostic.ai/) - Leaders in AI Data Governance and Security**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*