# Install dependencies
pip install shodan requests aiohttp

# Run the scanner
python mcp_scanner.py --api-key YOUR_SHODAN_API_KEY

# With custom options
python mcp_scanner.py --api-key YOUR_API_KEY --max-results 100 --max-concurrent 15 --output my_results.json