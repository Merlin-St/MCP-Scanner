#!/usr/bin/env python3
"""
MCP (Model Context Protocol) Server Discovery and Tool Invocation Script
Uses Shodan API to discover MCP servers and attempts to interact with them.

Requirements:
pip install shodan requests asyncio aiohttp

Usage:
python mcp_scanner.py --api-key YOUR_SHODAN_API_KEY
"""

import shodan
import requests
import json
import asyncio
import aiohttp
import argparse
import logging
import time
import csv
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional, Tuple
import re
from datetime import datetime
import os

# Configure logging with UTF-8 encoding
def setup_logging(timestamp: str):
    """Setup logging with timestamped log file"""
    log_filename = f'mcp_discovery_{timestamp}.log'
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return log_filename

# Set console output to UTF-8 for Windows compatibility
import sys
if sys.platform.startswith('win'):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

class MCPServerScanner:
    def __init__(self, shodan_api_key: str, timestamp: str):
        self.shodan_api = shodan.Shodan(shodan_api_key)
        self.discovered_servers = []
        self.verified_servers = []
        self.session = None
        self.timestamp = timestamp
        self.logger = logging.getLogger(__name__)
        
        # Create output directory if it doesn't exist
        self.output_dir = f'mcp_scan_results_{timestamp}'
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Comprehensive list of Shodan filters for MCP servers
        # Fixed to use proper Shodan API syntax
        self.shodan_filters = [
            # === CORE MCP IDENTIFICATION ===
            # Protocol name variations
            '"Model Context Protocol"',
            '"model context protocol"',
            'MCP server',
            'mcp-server',
            'MCPServer',
            '"mcp server"',
            
            # === TRANSPORT LAYER DETECTION ===
            # Server-Sent Events (SSE) - Primary transport
            'text/event-stream',
            'content-type: text/event-stream',
            'Server-Sent Events',
            'event-stream',
            
            # JSON-RPC protocol markers
            '"jsonrpc": "2.0"',
            'jsonrpc 2.0',
            'JSON-RPC 2.0',
            '"method": "initialize"',
            '"method": "tools/list"',
            '"method": "tools/call"',
            
            # === PROTOCOL VERSION DETECTION ===
            # MCP protocol version
            '"protocolVersion": "2024-11-05"',
            'protocolVersion 2024-11-05',
            '2024-11-05',
            
            # === ENDPOINT DETECTION ===
            # Common MCP endpoint paths
            'GET /mcp',
            'POST /mcp',
            'GET /sse',
            'POST /messages',
            '/mcp/sse',
            '/api/mcp',
            '/v1/mcp',
            
            # === INITIALIZATION PATTERNS ===
            # MCP initialization keywords
            '"clientInfo"',
            '"serverInfo"',
            'initialize capabilities',
            'capabilities tools resources',
            'tools resources',
            
            # === FRAMEWORK DETECTION ===
            # FastAPI with MCP
            'FastAPI mcp',
            'fastapi mcp',
            'FastMCP',
            'fastmcp',
            'uvicorn mcp',
            
            # Python MCP frameworks
            'mcp-framework',
            'python-mcp',
            'mcp-python',
            'anthropic/mcp',
            
            # === HTTP HEADERS ===
            # Specific header patterns for MCP
            'cache-control: no-cache',
            'connection: keep-alive',
            'access-control-allow-origin',
            
            # === PORT-SPECIFIC SEARCHES ===
            # Common development ports with MCP indicators
            'port:3000 jsonrpc',
            'port:8000 jsonrpc',
            'port:8080 jsonrpc',
            'port:5000 jsonrpc',
            'port:3000 text/event-stream',
            'port:8000 text/event-stream',
            'port:8080 text/event-stream',
            'port:5000 text/event-stream',
            
            # === CLOUD PLATFORMS ===
            # Common cloud platforms hosting MCP
            'cloudflare mcp',
            'workers.dev mcp',
            'vercel mcp',
            'heroku mcp',
            'railway mcp',
            
            # === COMBINED SEARCHES ===
            # Multi-keyword combinations
            'jsonrpc initialize capabilities',
            'text/event-stream jsonrpc',
            'sse jsonrpc',
            'tools list call',
            
            # === SPECIFIC IMPLEMENTATIONS ===
            # Known MCP server implementations
            'mcp-shodan',
            'shodan-mcp',
            'mcp-proxy',
            'mcp-sse',
            
            # === DEVELOPMENT INDICATORS ===
            # Development/testing indicators
            'mcp development',
            'mcp dev',
            'mcp-dev',
            'mcp test',
            'localhost mcp',
            
            # === CONTENT DETECTION ===
            # HTML content indicators
            'html:"Model Context Protocol"',
            'html:"mcp server"',
            'html:"jsonrpc"',
            'html:"text/event-stream"',
            
            # === TOOL DETECTION ===
            # Common MCP tool patterns
            'tools/list',
            'tools/call',
            'resources/list',
            'resources/read',
            'prompts/list',
            
            # === ANTHROPIC SPECIFIC ===
            # Anthropic-related patterns
            'anthropic mcp',
            'claude mcp',
            'anthropic/mcp',
            
            # === ERROR PATTERNS ===
            # Common MCP error responses that might be exposed
            'MCP error',
            'jsonrpc error',
            'invalid method',
            'method not found',
            
            # === STREAMING PATTERNS ===
            # Streaming and real-time patterns
            'stream json',
            'streaming jsonrpc',
            'real-time json',
            'websocket mcp',
            
            # === SECURITY HEADERS ===
            # CORS and security headers common in MCP servers
            'access-control-allow-methods',
            'access-control-allow-headers',
            'x-frame-options',
            
            # === NODE.JS SPECIFIC ===
            # Node.js MCP implementations
            'nodejs mcp',
            'node mcp',
            'express mcp',
            'fastify mcp',
            
            # === PYTHON SPECIFIC ===
            # Python MCP implementations
            'python mcp',
            'flask mcp',
            'django mcp',
            'starlette mcp',
            
            # === DEBUGGING ENDPOINTS ===
            # Debug/health check endpoints
            '/health mcp',
            '/status mcp',
            '/debug mcp',
            '/info mcp',
            
            # === BROAD SEARCHES ===
            # Broader searches for discovery
            'mcp',  # Very broad - use with caution
            'model context',
            'context protocol',
            
            # === GITHUB/DOCUMENTATION ===
            # Documentation and repository indicators
            'github mcp',
            'docs mcp',
            'documentation mcp',
            'readme mcp',
        ]

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'MCP-Scanner/1.0'}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def validate_api_key(self) -> bool:
        """Validate Shodan API key and check account info"""
        try:
            info = self.shodan_api.info()
            self.logger.info(f"Shodan API key valid. Query credits: {info.get('query_credits', 'Unknown')}")
            self.logger.info(f"Scan credits: {info.get('scan_credits', 'Unknown')}")
            return True
        except shodan.APIError as e:
            self.logger.error(f"Shodan API key validation failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error validating API key: {e}")
            return False

    def search_shodan(self, max_results_per_filter: int = 100) -> List[Dict]:
        """Search Shodan using all MCP-related filters"""
        all_results = []
        seen_ips = set()
        
        self.logger.info(f"Starting Shodan search with {len(self.shodan_filters)} filters...")
        
        for i, filter_query in enumerate(self.shodan_filters, 1):
            try:
                self.logger.info(f"[{i}/{len(self.shodan_filters)}] Searching: {filter_query}")
                
                # Retry logic for API connectivity issues
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        results = self.shodan_api.search(filter_query, limit=max_results_per_filter)
                        break
                    except shodan.APIError as e:
                        if "Unable to connect" in str(e) and attempt < max_retries - 1:
                            self.logger.warning(f"Connection failed, retrying in {(attempt + 1) * 2} seconds...")
                            time.sleep((attempt + 1) * 2)
                            continue
                        else:
                            raise e
                
                for result in results['matches']:
                    ip_port = f"{result['ip_str']}:{result['port']}"
                    if ip_port not in seen_ips:
                        seen_ips.add(ip_port)
                        result['shodan_filter'] = filter_query
                        all_results.append(result)
                        self.logger.info(f"Found new target: {ip_port}")
                
                # Rate limiting - increased delay
                time.sleep(2)
                
            except shodan.APIError as e:
                error_msg = str(e).lower()
                if "invalid" in error_msg or "syntax" in error_msg:
                    self.logger.warning(f"Invalid query syntax for filter '{filter_query}': {e}")
                elif "quota" in error_msg or "limit" in error_msg:
                    self.logger.error(f"API quota exceeded: {e}")
                    break  # Stop searching if quota is exceeded
                elif "unable to connect" in error_msg:
                    self.logger.error(f"Connection error for filter '{filter_query}': {e}")
                else:
                    self.logger.error(f"Shodan API error for filter '{filter_query}': {e}")
                continue
            except Exception as e:
                self.logger.error(f"Unexpected error for filter '{filter_query}': {e}")
                continue
        
        self.logger.info(f"Shodan search completed. Found {len(all_results)} unique targets.")
        self.discovered_servers = all_results
        return all_results

    def construct_urls(self, result: Dict) -> List[str]:
        """Construct possible MCP endpoint URLs from Shodan result"""
        ip = result['ip_str']
        port = result['port']
        
        # Determine protocol
        protocol = 'https' if port in [443, 8443] else 'http'
        base_url = f"{protocol}://{ip}:{port}"
        
        # Common MCP endpoint paths
        paths = [
            '/mcp',
            '/mcp/sse',
            '/messages',
            '/mcp/stream',
            '/api/mcp',
            '/v1/mcp',
            '/'
        ]
        
        return [urljoin(base_url, path) for path in paths]

    async def verify_mcp_server(self, urls: List[str], shodan_result: Dict) -> Optional[Dict]:
        """Verify if a server is actually running MCP"""
        for url in urls:
            try:
                # Try to connect and check for MCP characteristics
                mcp_info = await self.check_mcp_endpoint(url)
                if mcp_info:
                    self.logger.info(f"[OK] Verified MCP server at {url}")
                    return {
                        'url': url,
                        'shodan_data': shodan_result,
                        'mcp_info': mcp_info,
                        'verified_at': datetime.now().isoformat()
                    }
            except Exception as e:
                self.logger.debug(f"Failed to verify {url}: {e}")
                continue
        
        return None

    async def check_mcp_endpoint(self, url: str) -> Optional[Dict]:
        """Check if an endpoint supports MCP protocol"""
        try:
            # Method 1: Try SSE endpoint (GET request)
            mcp_info = await self.check_sse_endpoint(url)
            if mcp_info:
                return mcp_info
            
            # Method 2: Try JSON-RPC endpoint (POST request)
            mcp_info = await self.check_jsonrpc_endpoint(url)
            if mcp_info:
                return mcp_info
            
            # Method 3: Check HTTP content for MCP indicators
            mcp_info = await self.check_http_content(url)
            if mcp_info:
                return mcp_info
                
        except Exception as e:
            self.logger.debug(f"Error checking MCP endpoint {url}: {e}")
        
        return None

    async def check_sse_endpoint(self, url: str) -> Optional[Dict]:
        """Check for Server-Sent Events MCP endpoint"""
        headers = {
            'Accept': 'text/event-stream',
            'Cache-Control': 'no-cache'
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    if 'text/event-stream' in content_type:
                        # Read some data to check for MCP-specific events
                        data = await response.content.read(1024)
                        text_data = data.decode('utf-8', errors='ignore')
                        
                        if any(keyword in text_data.lower() for keyword in ['mcp', 'jsonrpc', 'initialize', 'capabilities']):
                            return {
                                'type': 'SSE',
                                'endpoint': url,
                                'content_type': content_type,
                                'sample_data': text_data[:500]
                            }
        except Exception as e:
            self.logger.debug(f"SSE check failed for {url}: {e}")
        
        return None

    async def check_jsonrpc_endpoint(self, url: str) -> Optional[Dict]:
        """Check for JSON-RPC MCP endpoint"""
        # MCP initialization request
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-scanner",
                    "version": "1.0.0"
                }
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        try:
            async with self.session.post(url, json=init_request, headers=headers) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if (isinstance(data, dict) and 
                            data.get('jsonrpc') == '2.0' and 
                            'result' in data):
                            return {
                                'type': 'JSON-RPC',
                                'endpoint': url,
                                'init_response': data,
                                'server_info': data.get('result', {}).get('serverInfo', {}),
                                'capabilities': data.get('result', {}).get('capabilities', {})
                            }
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            self.logger.debug(f"JSON-RPC check failed for {url}: {e}")
        
        return None

    async def check_http_content(self, url: str) -> Optional[Dict]:
        """Check HTTP content for MCP indicators"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check for MCP-related keywords in content
                    mcp_indicators = [
                        'model context protocol',
                        'mcp server',
                        'jsonrpc.*mcp',
                        'text/event-stream',
                        'initialize.*capabilities',
                        'tools.*resources'
                    ]
                    
                    found_indicators = []
                    for indicator in mcp_indicators:
                        if re.search(indicator, content, re.IGNORECASE):
                            found_indicators.append(indicator)
                    
                    if found_indicators:
                        return {
                            'type': 'HTTP',
                            'endpoint': url,
                            'indicators': found_indicators,
                            'content_sample': content[:1000]
                        }
        except Exception as e:
            self.logger.debug(f"HTTP content check failed for {url}: {e}")
        
        return None

    async def get_server_capabilities(self, server: Dict) -> Optional[Dict]:
        """Get capabilities and available tools from verified MCP server"""
        mcp_info = server['mcp_info']
        
        if mcp_info['type'] == 'JSON-RPC':
            # Already have capabilities from initialization
            return mcp_info.get('capabilities', {})
        
        elif mcp_info['type'] == 'SSE':
            # Try to get capabilities via POST to /messages endpoint
            url = mcp_info['endpoint']
            messages_url = url.replace('/mcp', '/messages') if '/mcp' in url else f"{url}/messages"
            
            capabilities_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }
            
            try:
                async with self.session.post(messages_url, json=capabilities_request) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('result', {})
            except Exception as e:
                self.logger.debug(f"Failed to get capabilities from {messages_url}: {e}")
        
        return None

    async def invoke_tool(self, server: Dict, tool_name: str, arguments: Dict = None) -> Optional[Dict]:
        """Attempt to invoke a tool on the MCP server"""
        if arguments is None:
            arguments = {}
        
        mcp_info = server['mcp_info']
        
        # Construct tool invocation request
        tool_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        # Determine endpoint URL
        if mcp_info['type'] == 'JSON-RPC':
            endpoint_url = mcp_info['endpoint']
        elif mcp_info['type'] == 'SSE':
            endpoint_url = mcp_info['endpoint'].replace('/mcp', '/messages')
        else:
            return None
        
        try:
            async with self.session.post(endpoint_url, json=tool_request) as response:
                if response.status == 200:
                    result = await response.json()
                    self.logger.info(f"[OK] Successfully invoked tool '{tool_name}' on {endpoint_url}")
                    return result
                else:
                    self.logger.warning(f"Tool invocation failed with status {response.status}")
        except Exception as e:
            self.logger.error(f"Error invoking tool '{tool_name}': {e}")
        
        return None

    async def scan_and_verify_servers(self, max_concurrent: int = 10) -> List[Dict]:
        """Main method to scan and verify MCP servers"""
        self.logger.info("Starting MCP server verification...")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def verify_server(shodan_result):
            async with semaphore:
                urls = self.construct_urls(shodan_result)
                return await self.verify_mcp_server(urls, shodan_result)
        
        # Verify all discovered servers
        verification_tasks = [verify_server(result) for result in self.discovered_servers]
        verification_results = await asyncio.gather(*verification_tasks, return_exceptions=True)
        
        # Filter out None results and exceptions
        verified_servers = [
            result for result in verification_results 
            if result is not None and not isinstance(result, Exception)
        ]
        
        self.logger.info(f"Verified {len(verified_servers)} MCP servers out of {len(self.discovered_servers)} candidates")
        self.verified_servers = verified_servers
        return verified_servers

    async def interact_with_servers(self):
        """Interact with verified MCP servers to discover and invoke tools"""
        self.logger.info("Starting interaction with verified MCP servers...")
        
        for i, server in enumerate(self.verified_servers, 1):
            self.logger.info(f"[{i}/{len(self.verified_servers)}] Interacting with {server['url']}")
            
            try:
                # Get server capabilities
                capabilities = await self.get_server_capabilities(server)
                server['capabilities'] = capabilities
                
                if capabilities and 'tools' in str(capabilities):
                    self.logger.info(f"Server has tools available: {server['url']}")
                    
                    # Try to extract tool names and invoke them
                    tools = self.extract_tool_names(capabilities)
                    server['available_tools'] = tools
                    
                    for tool_name in tools[:3]:  # Limit to first 3 tools
                        self.logger.info(f"Attempting to invoke tool: {tool_name}")
                        result = await self.invoke_tool(server, tool_name)
                        if result:
                            if 'tool_results' not in server:
                                server['tool_results'] = {}
                            server['tool_results'][tool_name] = result
                
            except Exception as e:
                self.logger.error(f"Error interacting with server {server['url']}: {e}")
                continue

    def extract_tool_names(self, capabilities: Dict) -> List[str]:
        """Extract tool names from capabilities response"""
        tools = []
        
        if isinstance(capabilities, dict):
            # Look for tools in various possible locations
            if 'tools' in capabilities:
                tool_list = capabilities['tools']
                if isinstance(tool_list, list):
                    for tool in tool_list:
                        if isinstance(tool, dict) and 'name' in tool:
                            tools.append(tool['name'])
                        elif isinstance(tool, str):
                            tools.append(tool)
        
        return tools

    def save_results_json(self) -> str:
        """Save all results to a JSON file with timestamp"""
        filename = os.path.join(self.output_dir, f'mcp_scan_results_{self.timestamp}.json')
        
        results = {
            'scan_timestamp': datetime.now().isoformat(),
            'scan_id': self.timestamp,
            'discovered_servers_count': len(self.discovered_servers),
            'verified_servers_count': len(self.verified_servers),
            'discovered_servers': self.discovered_servers,
            'verified_servers': self.verified_servers,
            'scan_metadata': {
                'filters_used': len(self.shodan_filters),
                'total_unique_targets': len(self.discovered_servers),
                'verification_success_rate': f"{len(self.verified_servers)}/{len(self.discovered_servers)}" if self.discovered_servers else "0/0"
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str, ensure_ascii=False)
        
        self.logger.info(f"JSON results saved to {filename}")
        return filename

    def save_results_csv(self) -> str:
        """Save verified servers to CSV format"""
        filename = os.path.join(self.output_dir, f'verified_mcp_servers_{self.timestamp}.csv')
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'url', 'ip_address', 'port', 'mcp_type', 'verified_at', 
                'server_info', 'available_tools', 'country', 'organization'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for server in self.verified_servers:
                shodan_data = server.get('shodan_data', {})
                mcp_info = server.get('mcp_info', {})
                
                row = {
                    'url': server.get('url', ''),
                    'ip_address': shodan_data.get('ip_str', ''),
                    'port': shodan_data.get('port', ''),
                    'mcp_type': mcp_info.get('type', ''),
                    'verified_at': server.get('verified_at', ''),
                    'server_info': json.dumps(mcp_info.get('server_info', {})),
                    'available_tools': ', '.join(server.get('available_tools', [])),
                    'country': shodan_data.get('location', {}).get('country_name', ''),
                    'organization': shodan_data.get('org', '')
                }
                writer.writerow(row)
        
        self.logger.info(f"CSV results saved to {filename}")
        return filename

    def save_summary_report(self) -> str:
        """Save a human-readable summary report"""
        filename = os.path.join(self.output_dir, f'scan_summary_{self.timestamp}.txt')
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"MCP Server Discovery Scan Report\n")
            f.write(f"=" * 50 + "\n\n")
            f.write(f"Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan ID: {self.timestamp}\n\n")
            
            f.write(f"SUMMARY STATISTICS\n")
            f.write(f"-" * 20 + "\n")
            f.write(f"Total Discovered Servers: {len(self.discovered_servers)}\n")
            f.write(f"Verified MCP Servers: {len(self.verified_servers)}\n")
            f.write(f"Verification Success Rate: {(len(self.verified_servers)/len(self.discovered_servers)*100):.1f}%\n" if self.discovered_servers else "Verification Success Rate: 0%\n")
            f.write(f"Shodan Filters Used: {len(self.shodan_filters)}\n\n")
            
            if self.verified_servers:
                f.write(f"VERIFIED MCP SERVERS\n")
                f.write(f"-" * 20 + "\n")
                for i, server in enumerate(self.verified_servers, 1):
                    f.write(f"{i}. {server['url']}\n")
                    f.write(f"   Type: {server['mcp_info']['type']}\n")
                    f.write(f"   IP: {server['shodan_data']['ip_str']}:{server['shodan_data']['port']}\n")
                    f.write(f"   Country: {server['shodan_data'].get('location', {}).get('country_name', 'Unknown')}\n")
                    if 'available_tools' in server:
                        f.write(f"   Tools: {', '.join(server['available_tools'])}\n")
                    f.write(f"   Verified: {server['verified_at']}\n\n")
            
            f.write(f"DISCOVERED SERVERS BY COUNTRY\n")
            f.write(f"-" * 30 + "\n")
            country_counts = {}
            for server in self.discovered_servers:
                country = server.get('location', {}).get('country_name', 'Unknown')
                country_counts[country] = country_counts.get(country, 0) + 1
            
            for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{country}: {count}\n")
        
        self.logger.info(f"Summary report saved to {filename}")
        return filename

    def save_all_results(self) -> Dict[str, str]:
        """Save results in all formats and return filenames"""
        files = {}
        files['json'] = self.save_results_json()
        files['csv'] = self.save_results_csv()
        files['summary'] = self.save_summary_report()
        
        # Save individual server details
        if self.verified_servers:
            details_dir = os.path.join(self.output_dir, 'server_details')
            os.makedirs(details_dir, exist_ok=True)
            
            for i, server in enumerate(self.verified_servers):
                server_file = os.path.join(details_dir, f'server_{i+1}_{self.timestamp}.json')
                with open(server_file, 'w', encoding='utf-8') as f:
                    json.dump(server, f, indent=2, default=str, ensure_ascii=False)
        
        return files

async def main():
    # Generate timestamp for this scan
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Setup logging with timestamp
    log_file = setup_logging(timestamp)
    logger = logging.getLogger(__name__)
    
    parser = argparse.ArgumentParser(description='MCP Server Discovery and Interaction Tool')
    parser.add_argument('--api-key', required=True, help='Shodan API key')
    parser.add_argument('--max-results', type=int, default=50, help='Max results per filter')
    parser.add_argument('--max-concurrent', type=int, default=10, help='Max concurrent connections')
    
    args = parser.parse_args()
    
    # Quote for good luck
    logger.info("\n*+"*5 + "\nI break down, falling into love now with falling apart\nI'm a popular, popular monster" + "\n*+" *5 + "\nPopular Monster by Falling in Reverse\n")
    
    async with MCPServerScanner(args.api_key, timestamp) as scanner:
        # Step 0: Validate API key
        logger.info("=== PHASE 0: API KEY VALIDATION ===")
        if not scanner.validate_api_key():
            logger.error("Invalid Shodan API key. Please check your API key and try again.")
            return
        
        # Step 1: Search Shodan
        logger.info("=== PHASE 1: SHODAN DISCOVERY ===")
        scanner.search_shodan(max_results_per_filter=args.max_results)
        
        # Step 2: Verify MCP servers
        logger.info("=== PHASE 2: MCP VERIFICATION ===")
        await scanner.scan_and_verify_servers(max_concurrent=args.max_concurrent)
        
        # Step 3: Interact with verified servers
        logger.info("=== PHASE 3: TOOL INTERACTION ===")
        await scanner.interact_with_servers()
        
        # Step 4: Save results in all formats
        logger.info("=== PHASE 4: SAVING RESULTS ===")
        output_files = scanner.save_all_results()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"MCP SCANNER RESULTS - {timestamp}")
        print(f"{'='*60}")
        print(f"Discovered servers: {len(scanner.discovered_servers)}")
        print(f"Verified MCP servers: {len(scanner.verified_servers)}")
        print(f"Output directory: {scanner.output_dir}")
        print(f"\nGenerated files:")
        for file_type, filename in output_files.items():
            print(f"  {file_type.upper()}: {filename}")
        print(f"  LOG: {log_file}")
        
        if scanner.verified_servers:
            print(f"\nVerified MCP Servers:")
            for server in scanner.verified_servers:
                print(f"  • {server['url']} ({server['mcp_info']['type']})")
                if 'available_tools' in server:
                    print(f"    Tools: {', '.join(server['available_tools'])}")

if __name__ == "__main__":
    asyncio.run(main())