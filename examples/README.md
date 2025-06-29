# MCP Scanner Examples

This directory contains example output files and usage demonstrations for the MCP Scanner tool.

## Sample Output Files

### `sample_output.json`
This file shows the structure and format of data returned by the MCP Scanner when it discovers and analyzes MCP servers. The example includes:

- **Server Information**: URL, IP, port, and transport protocol details
- **Protocol Data**: MCP version and server capabilities
- **Security Assessment**: SSL status, authentication, and risk evaluation
- **Tool Discovery**: Available tools and their input schemas
- **Resource Mapping**: Accessible resources and endpoints

**Note**: All data in this example is sanitized and uses fictitious servers for demonstration purposes.

## Risk Levels

The scanner assigns risk levels based on several factors:

- **Low**: Properly secured server with authentication and SSL
- **Medium**: Some security measures in place but with potential concerns
- **High**: Significant security issues such as:
  - No authentication required
  - Unencrypted HTTP connections
  - Potentially dangerous tools exposed (e.g., database queries)
  - No rate limiting

## Using the Examples

Security teams can use these examples to:

1. **Understand Output Format**: Plan automated processing of scan results
2. **Risk Assessment**: Develop criteria for evaluating discovered servers
3. **Reporting**: Create templates for security findings documentation
4. **Training**: Educate team members on MCP security implications

## Enterprise Integration

For Fortune 500 organizations using tools like Microsoft Copilot, understanding the broader AI ecosystem is crucial for:

- **Data Governance**: Ensuring no sensitive data leakage through misconfigured MCP servers
- **Compliance**: Meeting regulatory requirements for AI system security
- **Risk Management**: Identifying potential attack vectors in AI infrastructure

---

*For more information about AI security and data governance, visit [Knostic.ai](https://www.knostic.ai/)* 