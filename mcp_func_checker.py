#!/usr/bin/env python3
"""
MCP Server Inspector Tool
Properly connects to MCP servers using SSE transport and MCP protocol

A companion tool to MCP Scanner for targeted server inspection.
"""

import asyncio
import aiohttp
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse
import time
import uuid
from urllib.parse import urljoin

# Version info
__version__ = "1.0.0"
__author__ = "Knostic"

# Configuration
DEFAULT_TIMEOUT = 15
MCP_PROTOCOL_VERSION = "2024-11-05"

class MCPClient:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(ssl=False)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def create_mcp_request(self, method: str, params: Dict = None) -> Dict:
        """Create a proper MCP JSON-RPC 2.0 request"""
        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method
        }
        if params:
            request["params"] = params
        return request

    async def send_sse_request(self, url: str, request: Dict) -> Optional[Dict]:
        """Send MCP request via Server-Sent Events"""
        try:
            headers = {
                'Accept': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Content-Type': 'application/json'
            }
            
            # Try POST request first (some MCP servers expect POST)
            try:
                async with self.session.post(url, 
                                           json=request, 
                                           headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        return await self.parse_sse_response(content)
            except:
                pass
            
            # Try GET with query params
            try:
                async with self.session.get(f"{url}?message={json.dumps(request)}", 
                                          headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        return await self.parse_sse_response(content)
            except:
                pass
                
            # Try establishing SSE connection
            try:
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        # Send initialization request
                        init_request = self.create_mcp_request("initialize", {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {
                                "tools": {},
                                "resources": {},
                                "prompts": {}
                            },
                            "clientInfo": {
                                "name": "mcp-inspector",
                                "version": __version__
                            }
                        })
                        
                        content = await response.text()
                        return await self.parse_sse_response(content)
            except:
                pass
                
        except Exception as e:
            return None
        
        return None

    async def parse_sse_response(self, content: str) -> Dict:
        """Parse Server-Sent Events response"""
        lines = content.split('\n')
        events = []
        current_event = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('data: '):
                data = line[6:]  # Remove 'data: '
                try:
                    json_data = json.loads(data)
                    events.append(json_data)
                except json.JSONDecodeError:
                    continue
            elif line.startswith('event: '):
                current_event['event'] = line[7:]
            elif line == '':
                if current_event:
                    events.append(current_event)
                    current_event = {}
        
        return {"events": events, "raw_content": content}

    async def try_mcp_connection(self, base_url: str, path: str = "") -> Optional[Dict[str, Any]]:
        """Try to connect to an MCP server with proper protocol"""
        if not base_url.startswith('http'):
            url = f"http://{base_url}"
        else:
            url = base_url
            
        if path:
            url = urljoin(url, path)
        
        try:
            # Try different MCP methods
            methods_to_try = [
                ("tools/list", {}),
                ("resources/list", {}),
                ("prompts/list", {}),
                ("initialize", {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "clientInfo": {"name": "mcp-inspector", "version": __version__}
                })
            ]
            
            for method, params in methods_to_try:
                request = self.create_mcp_request(method, params)
                
                # Try SSE connection
                response = await self.send_sse_request(url, request)
                if response and response.get("events"):
                    return {
                        "url": url,
                        "method": method,
                        "success": True,
                        "response": response,
                        "transport": "sse"
                    }
                
                # Try regular HTTP POST
                try:
                    async with self.session.post(url, json=request) as http_response:
                        if http_response.status == 200:
                            try:
                                data = await http_response.json()
                                return {
                                    "url": url,
                                    "method": method,
                                    "success": True,
                                    "response": data,
                                    "transport": "http"
                                }
                            except:
                                pass
                except:
                    pass
        
        except Exception as e:
            return None
            
        return None

    async def extract_tools_from_response(self, response_data: Dict) -> List[str]:
        """Extract tool names from MCP response"""
        tools = []
        
        # Handle SSE events
        if "events" in response_data:
            for event in response_data["events"]:
                if isinstance(event, dict):
                    # Look for tools in result
                    if "result" in event and "tools" in event["result"]:
                        tool_list = event["result"]["tools"]
                        if isinstance(tool_list, list):
                            for tool in tool_list:
                                if isinstance(tool, dict) and "name" in tool:
                                    tools.append(tool["name"])
                    
                    # Look for capabilities
                    if "result" in event and "capabilities" in event["result"]:
                        caps = event["result"]["capabilities"]
                        if "tools" in caps:
                            tools.append("tools_capability")
                        if "resources" in caps:
                            tools.append("resources_capability")
                        if "prompts" in caps:
                            tools.append("prompts_capability")
        
        # Handle direct HTTP response
        if "result" in response_data:
            result = response_data["result"]
            if "tools" in result and isinstance(result["tools"], list):
                for tool in result["tools"]:
                    if isinstance(tool, dict) and "name" in tool:
                        tools.append(tool["name"])
            
            if "resources" in result and isinstance(result["resources"], list):
                for resource in result["resources"]:
                    if isinstance(resource, dict) and "name" in resource:
                        tools.append(f"resource:{resource['name']}")
            
            if "prompts" in result and isinstance(result["prompts"], list):
                for prompt in result["prompts"]:
                    if isinstance(prompt, dict) and "name" in prompt:
                        tools.append(f"prompt:{prompt['name']}")
        
        return list(set(tools))

    async def inspect_server(self, ip_port: str) -> Dict[str, Any]:
        """Inspect a single MCP server"""
        paths_to_try = ["", "/mcp", "/sse", "/mcp/sse"]
        results = {
            "server": ip_port,
            "accessible": False,
            "responses": [],
            "tools": [],
            "capabilities": [],
            "transport_type": None,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        print(f"Inspecting MCP server: {ip_port}")
        
        for path in paths_to_try:
            print(f"  Trying path: {path or '/'}")
            
            response = await self.try_mcp_connection(ip_port, path)
            
            if response and response.get("success"):
                results["accessible"] = True
                results["transport_type"] = response.get("transport", "unknown")
                results["responses"].append(response)
                
                # Extract tools from response
                tools = await self.extract_tools_from_response(response["response"])
                results["tools"].extend(tools)
                
                print(f"    ✓ Success via {response['transport']}: {response['method']}")
                if tools:
                    print(f"    Found: {', '.join(tools)}")
                
                # Don't try other paths if we found a working one
                break
            else:
                print(f"    ✗ Failed: {path or '/'}")
        
        # Remove duplicates
        results["tools"] = list(set(results["tools"]))
        
        return results

    async def inspect_all_servers(self, servers: List[str]) -> List[Dict[str, Any]]:
        """Inspect all servers with limited concurrency to avoid overwhelming them"""
        semaphore = asyncio.Semaphore(5)  # Limit to 5 concurrent connections
        
        async def inspect_with_semaphore(server):
            async with semaphore:
                return await self.inspect_server(server.strip())
        
        tasks = [inspect_with_semaphore(server) for server in servers if server.strip()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"Error processing server {servers[i]}: {result}")
            else:
                valid_results.append(result)
                
        return valid_results

def load_servers_from_file(file_path: str) -> List[str]:
    """Load IP:PORT combinations from file"""
    try:
        with open(file_path, 'r') as f:
            servers = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        return servers
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def save_results(results: List[Dict[str, Any]], output_file: str):
    """Save results to JSON file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

def print_summary(results: List[Dict[str, Any]]):
    """Print a summary of the inspection results"""
    total_servers = len(results)
    accessible_servers = len([r for r in results if r["accessible"]])
    servers_with_tools = len([r for r in results if r["tools"]])
    
    print(f"\n{'='*60}")
    print(f"MCP INSPECTION SUMMARY")
    print(f"{'='*60}")
    print(f"Total servers tested: {total_servers}")
    print(f"Accessible MCP servers: {accessible_servers}")
    print(f"Servers with tools/capabilities: {servers_with_tools}")
    
    # Transport type breakdown
    transports = {}
    for result in results:
        if result["accessible"]:
            transport = result.get("transport_type", "unknown")
            transports[transport] = transports.get(transport, 0) + 1
    
    if transports:
        print(f"\nTransport types:")
        for transport, count in transports.items():
            print(f"  {transport}: {count}")
    
    if servers_with_tools > 0:
        print(f"\nSERVERS WITH TOOLS/CAPABILITIES:")
        print(f"{'-'*40}")
        for result in results:
            if result["tools"]:
                print(f"Server: {result['server']}")
                print(f"Transport: {result.get('transport_type', 'unknown')}")
                print(f"Tools/Capabilities: {', '.join(result['tools'])}")
                print(f"Responses: {len(result['responses'])}")
                print()

async def main():
    parser = argparse.ArgumentParser(
        description="MCP Server Inspector Tool - Properly connects using MCP protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s --file servers.txt
  %(prog)s --servers "server1.com:8000,server2.com:3000"
  %(prog)s -f servers.txt -o results.json -t 30 --quiet

Input file format:
  server1.com:8000
  192.168.1.100:3000
  example.org:8080

Version: {__version__}
Author: {__author__}
        """)
    # Create mutually exclusive group for input methods
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", "-f", dest="input_file", 
                           help="Text file containing IP:PORT combinations (one per line)")
    input_group.add_argument("--servers", "-s", 
                           help="Comma-separated list of servers (e.g., 'server1:8000,server2:3000')")
    
    parser.add_argument("-o", "--output", default="mcp_inspection_results.json", 
                       help="Output JSON file (default: mcp_inspection_results.json)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, 
                       help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--quiet", "-q", action="store_true", 
                       help="Suppress detailed output during inspection")
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Log startup
    print(f"MCP Server Inspector v{__version__}")
    
    # Load servers from file or command line
    if args.input_file:
        servers = load_servers_from_file(args.input_file)
    else:
        servers = [s.strip() for s in args.servers.split(',') if s.strip()]
    
    if not servers:
        print("No servers found in the input file")
        sys.exit(1)
    
    print(f"Loaded {len(servers)} servers from {args.input_file}")
    print(f"Timeout: {args.timeout} seconds")
    print(f"Output file: {args.output}")
    print("Using proper MCP protocol (SSE/HTTP JSON-RPC)")
    print()
    
    # Run inspection
    async with MCPClient(timeout=args.timeout) as client:
        if args.quiet:
            import io
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                results = await client.inspect_all_servers(servers)
        else:
            results = await client.inspect_all_servers(servers)
    
    # Save and display results
    save_results(results, args.output)
    print_summary(results)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInspection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)