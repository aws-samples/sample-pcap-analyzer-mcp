# PCAP Analyzer MCP Server

[![PyPI](https://img.shields.io/pypi/v/awslabs.pcap-analyzer-mcp-server.svg)](https://pypi.org/project/awslabs.pcap-analyzer-mcp-server/)
[![License](https://img.shields.io/badge/License-MIT--0-blue.svg)](https://github.com/aws-samples/sample-pcap-analyzer-mcp/blob/main/LICENSE)

A Model Context Protocol (MCP) server for comprehensive network packet capture and analysis using Wireshark/tshark.

[GitHub Repository](https://github.com/aws-samples/sample-pcap-analyzer-mcp) •
[Full Documentation](https://github.com/aws-samples/sample-pcap-analyzer-mcp#readme)

## Overview

This MCP server enables AI models to perform sophisticated network packet capture and analysis. It provides **46 specialized tools** across 11 categories for deep network analysis, troubleshooting, and security assessment.

### Architecture

Two deployment patterns are supported:

1. **Local (IDE)** — Run alongside your IDE (Claude Desktop, VS Code, Cursor, Kiro, Amazon Q Developer). The MCP client communicates with the server via stdio, which invokes tshark for packet analysis.

2. **Cloud (AgentCore Gateway + Lambda)** — Deploy as a Lambda function behind AgentCore Gateway with OAuth2/Cognito inbound auth and IAM outbound auth. PCAPs are read from S3.

See the [full architecture diagrams on GitHub](https://github.com/aws-samples/sample-pcap-analyzer-mcp#architecture).

### Key Capabilities

- 🔧 Network interface discovery and live packet capture
- 📊 Comprehensive protocol analysis (TCP, TLS, QUIC/HTTP3, BGP, DNS, HTTP)
- 🔒 Security analysis (TLS handshakes, PQC detection, ARP spoofing, DNS tunneling, credential exposure)
- ⚡ Performance metrics (latency, throughput, bandwidth, connection reuse, quality)
- 🔍 Advanced diagnostics (MTU/fragmentation, connection timeouts, out-of-order packets)
- 🌐 Network intelligence (Geo/ASN mapping, ICMP error classification, TCP reset analysis)

## Prerequisites

- **Python 3.10+**
- **uv** — [Install uv](https://docs.astral.sh/uv/getting-started/installation/)
- **Wireshark/tshark**:
  - macOS: `brew install wireshark`
  - Linux: `sudo apt-get install tshark`
  - Windows: Download from [wireshark.org](https://www.wireshark.org/download.html)

### Packet Capture Permissions

| Platform | Command |
|----------|---------|
| **macOS** | `sudo dseditgroup -o edit -a $(whoami) -t user access_bpf` (restart required) |
| **Linux** | `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap` |
| **Windows** | Run as Administrator with Npcap installed |

## Quick Install

```bash
# Using uvx (recommended)
uvx awslabs.pcap-analyzer-mcp-server@latest

# Using pip
pip install awslabs.pcap-analyzer-mcp-server
awslabs.pcap-analyzer-mcp-server

# From source
git clone https://github.com/aws-samples/sample-pcap-analyzer-mcp.git
cd sample-pcap-analyzer-mcp
uv sync
uv run awslabs.pcap-analyzer-mcp-server
```

## Configuration

### Kiro

Add to `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "uvx",
      "args": ["awslabs.pcap-analyzer-mcp-server@latest"]
    }
  }
}
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "uvx",
      "args": ["awslabs.pcap-analyzer-mcp-server@latest"]
    }
  }
}
```

### Amazon Q Developer

Add to `~/.aws/amazonq/mcp.json`:

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "uvx",
      "args": ["awslabs.pcap-analyzer-mcp-server@latest"]
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PCAP_STORAGE_DIR` | Directory for storing captured PCAP files | `./pcap_storage` |
| `MAX_CAPTURE_DURATION` | Maximum capture duration in seconds | `3600` |
| `WIRESHARK_PATH` | Path to tshark executable | `tshark` |

## Tools (46 total)

### Network Interface Management (1)
- `list_network_interfaces` — Discover available network interfaces

### Packet Capture Management (4)
- `start_packet_capture` / `stop_packet_capture` / `get_capture_status` / `list_captured_files`

### Basic PCAP Analysis (4)
- `analyze_pcap_file` / `extract_http_requests` / `generate_traffic_timeline` / `search_packet_content`

### Network Performance (2)
- `analyze_network_performance` / `analyze_network_latency`

### TLS/SSL Security (6)
- `analyze_tls_handshakes` / `analyze_sni_mismatches` / `extract_certificate_details` / `analyze_tls_alerts` / `analyze_connection_lifecycle` / `extract_tls_cipher_analysis`

### TCP Protocol Analysis (5)
- `analyze_tcp_retransmissions` / `analyze_tcp_zero_window` / `analyze_tcp_window_scaling` / `analyze_packet_timing_issues` / `analyze_congestion_indicators`

### Advanced Network Analysis (5)
- `analyze_dns_resolution_issues` / `analyze_expert_information` / `analyze_protocol_anomalies` / `analyze_network_topology` / `analyze_security_threats`

### Performance & Quality Metrics (4)
- `generate_throughput_io_graph` / `analyze_bandwidth_utilization` / `analyze_application_response_times` / `analyze_network_quality_metrics`

### Network Diagnostics (6)
- `analyze_mtu_fragmentation` / `analyze_tcp_resets` / `analyze_duplicate_acks` / `analyze_icmp_errors` / `analyze_connection_timeouts` / `analyze_out_of_order_packets`

### Protocol & Stream Analysis (3)
- `analyze_quic_traffic` / `follow_tcp_stream` / `follow_udp_stream`

### Security Detection (3)
- `detect_arp_spoofing` / `detect_dns_tunneling` / `extract_credentials`

### Data Extraction & Intelligence (3)
- `extract_fields` / `analyze_connection_reuse` / `analyze_geo_asn_mapping`

## Usage Examples

```
"Analyze bgp.pcap and explain why the BGP connection is failing"
"Capture network traffic on eth0 for 60 seconds and analyze for security threats"
"Examine TLS handshakes in https-traffic.pcap and identify any certificate issues"
"Check for TCP retransmissions and analyze connection quality in the packet capture"
```

## AgentCore Gateway Deployment

For team-wide or production deployments using AWS Lambda + AgentCore Gateway with OAuth2/Cognito authentication, see the [full deployment guide on GitHub](https://github.com/aws-samples/sample-pcap-analyzer-mcp#option-3-agentcore-gateway-with-lambda).

## Contributing

We welcome community contributions! See [CONTRIBUTING.md](https://github.com/aws-samples/sample-pcap-analyzer-mcp/blob/main/CONTRIBUTING.md).

## License

This library is licensed under the MIT-0 License. See the [LICENSE](https://github.com/aws-samples/sample-pcap-analyzer-mcp/blob/main/LICENSE) file.
