# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""PCAP Analyzer MCP Server - Comprehensive network packet capture and analysis."""

import asyncio
import json
import logging
import os
import psutil
import time
from datetime import datetime
from mcp.server import Server
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
)
from pathlib import Path
from typing import Any, Dict, List, Optional


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global configuration
PCAP_STORAGE_DIR = os.getenv('PCAP_STORAGE_DIR', './pcap_storage')
MAX_CAPTURE_DURATION = int(os.getenv('MAX_CAPTURE_DURATION', '3600'))
WIRESHARK_PATH = os.getenv('WIRESHARK_PATH', 'tshark')

# Ensure storage directory exists
Path(PCAP_STORAGE_DIR).mkdir(parents=True, exist_ok=True)

# Active capture sessions
active_captures: Dict[str, Dict[str, Any]] = {}


class PCAPAnalyzerServer:
    """PCAP Analyzer MCP Server with 31 comprehensive network analysis tools."""

    def __init__(self):
        """Initialize the PCAP Analyzer server."""
        self.server = Server('pcap-analyzer-mcp-server')
        self._setup_tools()

    def _setup_tools(self):
        """Set up all 31 network analysis tools."""

        # Network Interface Management (1 tool)
        @self.server.list_tools()  # pragma: no cover
        async def handle_list_tools() -> list[Tool]:  # pragma: no cover
            """List all available PCAP analysis tools."""
            return [
                # Network Interface Management
                Tool(
                    name='list_network_interfaces',
                    description='List available network interfaces for packet capture',
                    inputSchema={
                        'type': 'object',
                        'properties': {},
                    },
                ),
                # Packet Capture Management (4 tools)
                Tool(
                    name='start_packet_capture',
                    description='Start packet capture on specified interface',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'interface': {
                                'type': 'string',
                                'description': "Network interface to capture on (e.g., 'en0')",
                            },
                            'duration': {
                                'type': 'integer',
                                'description': 'Capture duration in seconds (default: 60)',
                                'default': 60,
                            },
                            'capture_filter': {
                                'type': 'string',
                                'description': "BPF filter for capture (e.g., 'tcp port 80')",
                            },
                            'output_file': {
                                'type': 'string',
                                'description': 'Custom output filename (optional)',
                            },
                        },
                        'required': ['interface'],
                    },
                ),
                Tool(
                    name='stop_packet_capture',
                    description='Stop an active packet capture session',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'capture_id': {
                                'type': 'string',
                                'description': 'ID of the capture session to stop',
                            },
                        },
                        'required': ['capture_id'],
                    },
                ),
                Tool(
                    name='get_capture_status',
                    description='Get status of all active capture sessions',
                    inputSchema={
                        'type': 'object',
                        'properties': {},
                    },
                ),
                Tool(
                    name='list_captured_files',
                    description='List all captured pcap files in storage directory',
                    inputSchema={
                        'type': 'object',
                        'properties': {},
                    },
                ),
                # Basic PCAP Analysis (4 tools)
                Tool(
                    name='analyze_pcap_file',
                    description='Analyze a pcap file and generate insights',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file or filename in storage',
                            },
                            'analysis_type': {
                                'type': 'string',
                                'description': 'Type of analysis (summary, protocols)',
                                'default': 'summary',
                            },
                            'display_filter': {
                                'type': 'string',
                                'description': "Wireshark display filter (e.g., 'tcp.port == 80')",
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='extract_http_requests',
                    description='Extract HTTP requests from pcap file',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'limit': {
                                'type': 'integer',
                                'description': 'Maximum number of requests to extract',
                                'default': 100,
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='generate_traffic_timeline',
                    description='Generate traffic timeline with specified time intervals',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'time_interval': {
                                'type': 'integer',
                                'description': 'Time interval in seconds for timeline',
                                'default': 60,
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='search_packet_content',
                    description='Search for specific patterns in packet content',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'search_pattern': {
                                'type': 'string',
                                'description': 'Pattern to search for in packet content',
                            },
                            'case_sensitive': {
                                'type': 'boolean',
                                'description': 'Whether search should be case sensitive',
                                'default': False,
                            },
                            'limit': {
                                'type': 'integer',
                                'description': 'Maximum number of matches to return',
                                'default': 50,
                            },
                        },
                        'required': ['pcap_file', 'search_pattern'],
                    },
                ),
                # Network Performance Analysis (2 tools)
                Tool(
                    name='analyze_network_performance',
                    description='Analyze network performance metrics from pcap file',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_network_latency',
                    description='Analyze network latency and response times',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                # TLS/SSL Security Analysis (6 tools)
                Tool(
                    name='analyze_tls_handshakes',
                    description='Analyze TLS handshakes including SNI, key exchange groups, and Post-Quantum Cryptography (PQC) detection',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_sni_mismatches',
                    description='Analyze SNI mismatches and correlate with connection resets',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='extract_certificate_details',
                    description='Extract SSL certificate details and validate against SNI',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_tls_alerts',
                    description='Analyze TLS alert messages that indicate handshake failures',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_connection_lifecycle',
                    description='Analyze complete connection lifecycle from SYN to FIN/RST',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='extract_tls_cipher_analysis',
                    description='Analyze TLS cipher suite negotiations, key exchange groups, and PQC algorithm usage',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                # TCP Protocol Analysis (5 tools)
                Tool(
                    name='analyze_tcp_retransmissions',
                    description='Analyze TCP retransmissions and packet loss patterns',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_tcp_zero_window',
                    description='Analyze TCP zero window conditions and flow control issues',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_tcp_window_scaling',
                    description='Analyze TCP window scaling and flow control mechanisms',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_packet_timing_issues',
                    description='Analyze packet timing issues and duplicate packets',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_congestion_indicators',
                    description='Analyze network congestion indicators and quality metrics',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                # Advanced Network Analysis (5 tools)
                Tool(
                    name='analyze_dns_resolution_issues',
                    description='Analyze DNS resolution issues and query patterns',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_expert_information',
                    description='Analyze Wireshark expert information for network issues',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'severity_filter': {
                                'type': 'string',
                                'description': 'Filter by severity (Chat, Note, Warn, Error)',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_protocol_anomalies',
                    description='Analyze protocol anomalies and malformed packets',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_network_topology',
                    description='Analyze network topology and routing information',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_security_threats',
                    description='Analyze potential security threats and suspicious activities',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                # Performance & Quality Metrics (4 tools)
                Tool(
                    name='generate_throughput_io_graph',
                    description='Generate throughput I/O graph data with specified time intervals',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'time_interval': {
                                'type': 'integer',
                                'description': 'Time interval in seconds for I/O graph',
                                'default': 1,
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_bandwidth_utilization',
                    description='Analyze bandwidth utilization and traffic patterns',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'time_window': {
                                'type': 'integer',
                                'description': 'Time window in seconds for bandwidth calculation',
                                'default': 10,
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_application_response_times',
                    description='Analyze application layer response times and performance',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'protocol': {
                                'type': 'string',
                                'description': 'Protocol to analyze (http, https, dns, ftp)',
                                'default': 'http',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_network_quality_metrics',
                    description='Analyze network quality metrics including jitter and packet loss',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                # Advanced Network Diagnostics (6 tools)
                Tool(
                    name='analyze_mtu_fragmentation',
                    description='Analyze MTU/fragmentation issues including Path MTU discovery failures, IP fragmentation, and ICMP "packet too big" messages',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_tcp_resets',
                    description='Analyze TCP connection resets (RST) with context: who sent the reset, connection duration, bytes transferred, and likely cause',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_duplicate_acks',
                    description='Analyze duplicate ACKs and fast retransmit patterns to distinguish real packet loss from reordering',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_icmp_errors',
                    description='Analyze ICMP error messages: destination unreachable, TTL exceeded, redirects, and parameter problems',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_connection_timeouts',
                    description='Detect connection timeouts: unanswered SYNs (firewall drops), idle connection timeouts, and half-open connections',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_out_of_order_packets',
                    description='Detect TCP out-of-order packets that indicate network path issues or reordering without actual loss',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_quic_traffic',
                    description='Analyze QUIC/HTTP3 traffic: connection IDs, handshake failures, version negotiation, stream multiplexing, and connection migration',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_connection_reuse',
                    description='Analyze HTTP connection pooling and reuse: requests per connection, keep-alive effectiveness, idle time before close, and connection churn',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='analyze_geo_asn_mapping',
                    description='Map IP addresses to ASN/organization using whois data to identify providers, CDNs, and traffic routing paths',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'top_n': {
                                'type': 'integer',
                                'description': 'Number of top IPs to resolve (default: 20)',
                                'default': 20,
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='follow_tcp_stream',
                    description='Reassemble and follow a TCP stream by stream index, showing the full conversation payload between client and server',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'stream_index': {
                                'type': 'integer',
                                'description': 'TCP stream index to follow',
                            },
                        },
                        'required': ['pcap_file', 'stream_index'],
                    },
                ),
                Tool(
                    name='follow_udp_stream',
                    description='Reassemble and follow a UDP stream by stream index',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'stream_index': {
                                'type': 'integer',
                                'description': 'UDP stream index to follow',
                            },
                        },
                        'required': ['pcap_file', 'stream_index'],
                    },
                ),
                Tool(
                    name='extract_fields',
                    description='Extract arbitrary tshark fields from packets with optional display filter. Supports any valid tshark field name.',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                            'fields': {
                                'type': 'array',
                                'items': {'type': 'string'},
                                'description': "List of tshark field names to extract (e.g., ['ip.src', 'tcp.port', 'http.host'])",
                            },
                            'display_filter': {
                                'type': 'string',
                                'description': "Optional Wireshark display filter (e.g., 'http.request')",
                            },
                            'limit': {
                                'type': 'integer',
                                'description': 'Maximum number of packets to return (default: 100)',
                                'default': 100,
                            },
                        },
                        'required': ['pcap_file', 'fields'],
                    },
                ),
                Tool(
                    name='detect_arp_spoofing',
                    description='Detect ARP spoofing: duplicate IP-to-MAC mappings, gratuitous ARP floods, and ARP reply storms',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='detect_dns_tunneling',
                    description='Detect DNS tunneling: unusually long domain queries, high TXT record volume, excessive subdomain entropy, and single-host query floods',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
                Tool(
                    name='extract_credentials',
                    description='Detect plaintext credentials in HTTP Basic Auth, FTP USER/PASS, Telnet, and SMTP AUTH traffic',
                    inputSchema={
                        'type': 'object',
                        'properties': {
                            'pcap_file': {
                                'type': 'string',
                                'description': 'Path to pcap file',
                            },
                        },
                        'required': ['pcap_file'],
                    },
                ),
            ]

        @self.server.call_tool()  # pragma: no cover
        async def handle_call_tool(
            name: str, arguments: dict
        ) -> list[TextContent]:  # pragma: no cover
            """Handle tool calls for PCAP analysis operations."""
            try:
                if name == 'list_network_interfaces':
                    return await self._list_network_interfaces()
                elif name == 'start_packet_capture':
                    return await self._start_packet_capture(**arguments)
                elif name == 'stop_packet_capture':
                    return await self._stop_packet_capture(**arguments)
                elif name == 'get_capture_status':
                    return await self._get_capture_status()
                elif name == 'list_captured_files':
                    return await self._list_captured_files()
                elif name == 'analyze_pcap_file':
                    return await self._analyze_pcap_file(**arguments)
                elif name == 'extract_http_requests':
                    return await self._extract_http_requests(**arguments)
                elif name == 'generate_traffic_timeline':
                    return await self._generate_traffic_timeline(**arguments)
                elif name == 'search_packet_content':
                    return await self._search_packet_content(**arguments)
                elif name == 'analyze_network_performance':
                    return await self._analyze_network_performance(**arguments)
                elif name == 'analyze_network_latency':
                    return await self._analyze_network_latency(**arguments)
                elif name == 'analyze_tls_handshakes':
                    return await self._analyze_tls_handshakes(**arguments)
                elif name == 'analyze_sni_mismatches':
                    return await self._analyze_sni_mismatches(**arguments)
                elif name == 'extract_certificate_details':
                    return await self._extract_certificate_details(**arguments)
                elif name == 'analyze_tls_alerts':
                    return await self._analyze_tls_alerts(**arguments)
                elif name == 'analyze_connection_lifecycle':
                    return await self._analyze_connection_lifecycle(**arguments)
                elif name == 'extract_tls_cipher_analysis':
                    return await self._extract_tls_cipher_analysis(**arguments)
                elif name == 'analyze_tcp_retransmissions':
                    return await self._analyze_tcp_retransmissions(**arguments)
                elif name == 'analyze_tcp_zero_window':
                    return await self._analyze_tcp_zero_window(**arguments)
                elif name == 'analyze_tcp_window_scaling':
                    return await self._analyze_tcp_window_scaling(**arguments)
                elif name == 'analyze_packet_timing_issues':
                    return await self._analyze_packet_timing_issues(**arguments)
                elif name == 'analyze_congestion_indicators':
                    return await self._analyze_congestion_indicators(**arguments)
                elif name == 'analyze_dns_resolution_issues':
                    return await self._analyze_dns_resolution_issues(**arguments)
                elif name == 'analyze_expert_information':
                    return await self._analyze_expert_information(**arguments)
                elif name == 'analyze_protocol_anomalies':
                    return await self._analyze_protocol_anomalies(**arguments)
                elif name == 'analyze_network_topology':
                    return await self._analyze_network_topology(**arguments)
                elif name == 'analyze_security_threats':
                    return await self._analyze_security_threats(**arguments)
                elif name == 'generate_throughput_io_graph':
                    return await self._generate_throughput_io_graph(**arguments)
                elif name == 'analyze_bandwidth_utilization':
                    return await self._analyze_bandwidth_utilization(**arguments)
                elif name == 'analyze_application_response_times':
                    return await self._analyze_application_response_times(**arguments)
                elif name == 'analyze_network_quality_metrics':
                    return await self._analyze_network_quality_metrics(**arguments)
                elif name == 'analyze_mtu_fragmentation':
                    return await self._analyze_mtu_fragmentation(**arguments)
                elif name == 'analyze_tcp_resets':
                    return await self._analyze_tcp_resets(**arguments)
                elif name == 'analyze_duplicate_acks':
                    return await self._analyze_duplicate_acks(**arguments)
                elif name == 'analyze_icmp_errors':
                    return await self._analyze_icmp_errors(**arguments)
                elif name == 'analyze_connection_timeouts':
                    return await self._analyze_connection_timeouts(**arguments)
                elif name == 'analyze_out_of_order_packets':
                    return await self._analyze_out_of_order_packets(**arguments)
                elif name == 'analyze_quic_traffic':
                    return await self._analyze_quic_traffic(**arguments)
                elif name == 'analyze_connection_reuse':
                    return await self._analyze_connection_reuse(**arguments)
                elif name == 'analyze_geo_asn_mapping':
                    return await self._analyze_geo_asn_mapping(**arguments)
                elif name == 'follow_tcp_stream':
                    return await self._follow_tcp_stream(**arguments)
                elif name == 'follow_udp_stream':
                    return await self._follow_udp_stream(**arguments)
                elif name == 'extract_fields':
                    return await self._extract_fields(**arguments)
                elif name == 'detect_arp_spoofing':
                    return await self._detect_arp_spoofing(**arguments)
                elif name == 'detect_dns_tunneling':
                    return await self._detect_dns_tunneling(**arguments)
                elif name == 'extract_credentials':
                    return await self._extract_credentials(**arguments)
                else:
                    raise ValueError(f'Unknown tool: {name}')
            except Exception as e:
                logger.error(f'Error in tool {name}: {str(e)}')
                return [TextContent(type='text', text=f'Error: {str(e)}')]

    async def _run_tshark_command(self, args: List[str]) -> str:
        """Run tshark command with input validation and security checks."""
        try:
            # Security: Validate wireshark path is safe
            if not WIRESHARK_PATH or not isinstance(WIRESHARK_PATH, str):
                raise ValueError('Invalid WIRESHARK_PATH configuration')

            # Security: Sanitize command arguments
            safe_args = []
            for arg in args:
                if not isinstance(arg, str):
                    raise ValueError(f'Invalid argument type: {type(arg)}')
                # Remove potentially dangerous characters
                if any(char in arg for char in [';', '&', '|', '`', '$']):
                    raise ValueError(f'Potentially unsafe argument: {arg}')
                safe_args.append(arg)

            cmd = [WIRESHARK_PATH] + safe_args
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                raise RuntimeError(f'tshark command failed: {stderr.decode()}')

            return stdout.decode()
        except Exception as e:
            raise RuntimeError(f'Failed to execute tshark: {str(e)}')

    def _resolve_pcap_path(self, pcap_file: str) -> str:
        """Resolve pcap file path with security validation."""
        # Security: Validate file extension first
        if not (pcap_file.endswith('.pcap') or pcap_file.endswith('.pcapng')):
            raise ValueError('Only .pcap and .pcapng files are allowed')

        # Security: Prevent path traversal attacks
        if '../' in pcap_file or '/..' in pcap_file:
            raise ValueError('Path traversal patterns not allowed')

        # Security: Only allow safe characters in filename
        import string

        allowed_chars = string.ascii_letters + string.digits + '.-_/'
        if not all(c in allowed_chars for c in pcap_file):
            raise ValueError('Invalid characters in file path')

        # Handle relative paths by checking storage directory first
        if not os.path.isabs(pcap_file):
            # Check in controlled storage directory
            storage_path = os.path.join(PCAP_STORAGE_DIR, pcap_file)
            if os.path.exists(storage_path):
                return storage_path

            # Check current directory (only for .pcap files)
            if os.path.exists(pcap_file):
                return os.path.realpath(pcap_file)
        else:
            # For absolute paths, ensure they exist and are .pcap files
            if os.path.exists(pcap_file):
                return os.path.realpath(pcap_file)

        raise FileNotFoundError(f'PCAP file not found: {pcap_file}')

    async def _list_network_interfaces(self) -> List[TextContent]:
        """List available network interfaces."""
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                stats = psutil.net_if_stats().get(interface)
                if stats and stats.isup:
                    interfaces.append(
                        {
                            'name': interface,
                            'addresses': [addr.address for addr in addrs],
                            'is_up': stats.isup,
                            'speed': stats.speed if stats.speed > 0 else 'Unknown',
                        }
                    )

            result = {'interfaces': interfaces, 'total_count': len(interfaces)}

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error listing interfaces: {str(e)}')]

    def _validate_interface(self, interface: str) -> str:
        """Validate network interface against available system interfaces."""
        import string

        # Allow only safe characters in interface names
        allowed_chars = string.ascii_letters + string.digits + '-_.'
        if not all(c in allowed_chars for c in interface):
            raise ValueError(f'Invalid characters in interface name: {interface!r}')

        # Allowlist check: interface must be one of the available system interfaces
        available = set(psutil.net_if_addrs().keys())
        if interface not in available:
            raise ValueError(
                f'Interface {interface!r} not found. Available interfaces: {sorted(available)}'
            )
        return interface

    def _validate_capture_filter(self, capture_filter: str) -> str:
        """Validate BPF capture filter expression for safety."""
        # Reject shell metacharacters that could be injected
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r', '\x00']
        for char in dangerous_chars:
            if char in capture_filter:
                raise ValueError(
                    f'Invalid character {char!r} in capture filter. '
                    'Only BPF filter expressions are allowed.'
                )

        # Enforce a reasonable length limit
        if len(capture_filter) > 512:
            raise ValueError('Capture filter expression is too long (max 512 characters)')

        return capture_filter

    def _sanitize_output_filename(self, output_file: str) -> str:
        """Sanitize output filename using the same rules as _resolve_pcap_path."""
        import string

        # Must end with .pcap
        if not output_file.endswith('.pcap'):
            raise ValueError('Output filename must have a .pcap extension')

        # Prevent path traversal
        if '../' in output_file or '/..' in output_file or output_file.startswith('/'):
            raise ValueError('Path traversal or absolute paths are not allowed in output filename')

        # Only allow safe characters (no directory separators beyond a flat filename)
        allowed_chars = string.ascii_letters + string.digits + '.-_'
        basename = os.path.basename(output_file)
        if not all(c in allowed_chars for c in basename):
            raise ValueError(f'Invalid characters in output filename: {basename!r}')

        return basename

    async def _start_packet_capture(
        self,
        interface: str,
        duration: int = 60,
        capture_filter: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> List[TextContent]:
        """Start packet capture on specified interface."""
        try:
            # Security: Validate interface against available system interfaces
            interface = self._validate_interface(interface)

            # Security: Validate BPF capture filter syntax
            if capture_filter is not None:
                capture_filter = self._validate_capture_filter(capture_filter)

            # Generate capture ID and sanitize output filename
            capture_id = f'capture_{int(time.time())}'
            if not output_file:
                output_file = f'{capture_id}.pcap'

            # Security: Sanitize output filename (prevent path traversal)
            safe_filename = self._sanitize_output_filename(output_file)
            output_path = os.path.join(PCAP_STORAGE_DIR, safe_filename)

            # Build tshark command
            cmd = [WIRESHARK_PATH, '-i', interface, '-w', output_path]
            if capture_filter:
                cmd.extend(['-f', capture_filter])

            # Start capture process
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            # Store capture info
            active_captures[capture_id] = {
                'process': process,
                'interface': interface,
                'output_file': output_path,
                'start_time': datetime.now().isoformat(),
                'duration': duration,
                'filter': capture_filter,
            }

            # Schedule stop after duration
            asyncio.create_task(self._auto_stop_capture(capture_id, duration))

            result = {
                'capture_id': capture_id,
                'status': 'started',
                'interface': interface,
                'output_file': output_path,
                'duration': duration,
                'filter': capture_filter,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error starting capture: {str(e)}')]

    async def _auto_stop_capture(self, capture_id: str, duration: int):
        """Automatically stop capture after specified duration."""
        await asyncio.sleep(duration)
        if capture_id in active_captures:
            await self._stop_packet_capture(capture_id)

    async def _stop_packet_capture(self, capture_id: str) -> List[TextContent]:
        """Stop an active packet capture session."""
        try:
            if capture_id not in active_captures:
                return [TextContent(type='text', text=f'Capture {capture_id} not found')]

            capture_info = active_captures[capture_id]
            process = capture_info['process']

            # Terminate the process
            process.terminate()
            await process.wait()

            # Remove from active captures
            del active_captures[capture_id]

            result = {
                'capture_id': capture_id,
                'status': 'stopped',
                'output_file': capture_info['output_file'],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error stopping capture: {str(e)}')]

    async def _analyze_pcap_file(
        self, pcap_file: str, analysis_type: str = 'summary', display_filter: Optional[str] = None
    ) -> List[TextContent]:
        """Analyze a pcap file and generate insights."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Build analysis command based on type
            if analysis_type == 'summary':
                args = ['-r', pcap_path, '-q', '-z', 'conv,tcp', '-z', 'proto,colinfo']
            elif analysis_type == 'protocols':
                args = ['-r', pcap_path, '-q', '-z', 'proto,colinfo']
            elif analysis_type == 'conversations':
                args = ['-r', pcap_path, '-q', '-z', 'conv,tcp', '-z', 'conv,udp']
            else:
                args = ['-r', pcap_path, '-q']

            if display_filter:
                args.extend(['-Y', display_filter])

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': analysis_type,
                'filter': display_filter,
                'analysis_output': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing PCAP: {str(e)}')]

    async def _get_capture_status(self) -> List[TextContent]:
        """Get status of all active capture sessions."""
        try:
            result = {'active_captures': len(active_captures), 'captures': []}

            for capture_id, info in active_captures.items():
                result['captures'].append(
                    {
                        'capture_id': capture_id,
                        'interface': info['interface'],
                        'start_time': info['start_time'],
                        'duration': info['duration'],
                        'output_file': info['output_file'],
                        'filter': info.get('filter'),
                    }
                )

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error getting capture status: {str(e)}')]

    async def _list_captured_files(self) -> List[TextContent]:
        """List all captured pcap files in storage directory."""
        try:
            files = []
            storage_path = Path(PCAP_STORAGE_DIR)

            if storage_path.exists():
                for file_path in storage_path.glob('*.pcap'):
                    stat = file_path.stat()
                    files.append(
                        {
                            'filename': file_path.name,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'path': str(file_path),
                        }
                    )

            result = {
                'storage_directory': PCAP_STORAGE_DIR,
                'total_files': len(files),
                'files': files,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error listing captured files: {str(e)}')]

    async def _extract_http_requests(self, pcap_file: str, limit: int = 100) -> List[TextContent]:
        """Extract HTTP requests from pcap file."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'http.request',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'http.request.method',
                '-e',
                'http.request.uri',
                '-e',
                'http.host',
                '-c',
                str(limit),
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'limit': limit,
                'http_requests': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error extracting HTTP requests: {str(e)}')]

    async def _generate_traffic_timeline(
        self, pcap_file: str, time_interval: int = 60
    ) -> List[TextContent]:
        """Generate traffic timeline with specified time intervals."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', f'io,stat,{time_interval}']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'time_interval': time_interval,
                'timeline_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error generating traffic timeline: {str(e)}')]

    async def _search_packet_content(
        self, pcap_file: str, search_pattern: str, case_sensitive: bool = False, limit: int = 50
    ) -> List[TextContent]:
        """Search for specific patterns in packet content."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Build search filter
            if case_sensitive:
                filter_expr = f'frame contains "{search_pattern}"'
            else:
                filter_expr = f'frame contains "{search_pattern.lower()}"'

            args = ['-r', pcap_path, '-Y', filter_expr, '-c', str(limit)]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'search_pattern': search_pattern,
                'case_sensitive': case_sensitive,
                'limit': limit,
                'matches': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error searching packet content: {str(e)}')]

    async def _analyze_network_performance(self, pcap_file: str) -> List[TextContent]:
        """Analyze network performance metrics from pcap file."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', 'conv,tcp', '-z', 'rtp,streams']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'network_performance',
                'performance_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing network performance: {str(e)}')
            ]

    async def _analyze_network_latency(self, pcap_file: str) -> List[TextContent]:
        """Analyze network latency and response times."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', 'rtt,tcp']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'network_latency',
                'latency_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing network latency: {str(e)}')]

    # TLS/SSL Analysis Methods
    async def _analyze_tls_handshakes(self, pcap_file: str) -> List[TextContent]:
        """Analyze TLS handshakes including SNI, key exchange groups, and PQC detection."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tls.handshake',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tls.handshake.type',
                '-e',
                'tls.handshake.extensions_server_name',
                '-e',
                'tls.handshake.extensions_supported_group',
                '-e',
                'tls.handshake.version',
            ]

            output = await self._run_tshark_command(args)

            # PQC NamedGroup identifiers (tshark outputs decimal values)
            PQC_GROUPS = {
                '25497',   # 0x6399 - X25519Kyber768Draft00
                '17800',   # 0x4588 - X25519MLKEM768
                '25600',   # 0x6400 - SecP256r1MLKEM768
                '25601',   # 0x6401 - X25519MLKEM768 (alt)
                '512',     # 0x0200 - MLKEM512
                '513',     # 0x0201 - MLKEM768
                '514',     # 0x0202 - MLKEM1024
                '12107',   # 0x2f4b - SecP256r1Kyber768
                '12108',   # 0x2f4c - SecP384r1Kyber1024
                '4588',    # alternate decimal representation
            }

            handshake_data = []
            pqc_detected = False
            if output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split('\t')
                    entry = {
                        'time': parts[0] if len(parts) > 0 else '',
                        'src': parts[1] if len(parts) > 1 else '',
                        'dst': parts[2] if len(parts) > 2 else '',
                        'type': parts[3] if len(parts) > 3 else '',
                        'sni': parts[4] if len(parts) > 4 else '',
                        'supported_groups': parts[5] if len(parts) > 5 else '',
                        'tls_version': parts[6] if len(parts) > 6 else '',
                    }
                    # Check for PQC in supported_groups
                    groups_str = entry['supported_groups']
                    if any(g.strip() in PQC_GROUPS for g in groups_str.split(',')):
                        entry['pqc_key_exchange'] = True
                        pqc_detected = True
                    handshake_data.append(entry)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tls_handshakes',
                'pqc_detected': pqc_detected,
                'total_handshake_messages': len(handshake_data),
                'handshake_data': handshake_data[:200],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing TLS handshakes: {str(e)}')]

    async def _analyze_sni_mismatches(self, pcap_file: str) -> List[TextContent]:
        """Analyze SNI mismatches and correlate with connection resets."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tls.handshake.extensions_server_name or tcp.flags.reset eq 1',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tls.handshake.extensions_server_name',
                '-e',
                'tcp.flags.reset',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'sni_mismatches',
                'sni_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing SNI mismatches: {str(e)}')]

    async def _extract_certificate_details(self, pcap_file: str) -> List[TextContent]:
        """Extract SSL certificate details and validate against SNI."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tls.handshake.certificate',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'x509sat.printableString',
                '-e',
                'x509sat.uTF8String',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'certificate_details',
                'certificate_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error extracting certificate details: {str(e)}')
            ]

    async def _analyze_tls_alerts(self, pcap_file: str) -> List[TextContent]:
        """Analyze TLS alert messages that indicate handshake failures."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tls.alert_message',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tls.alert_message.level',
                '-e',
                'tls.alert_message.desc',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tls_alerts',
                'alert_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing TLS alerts: {str(e)}')]

    async def _analyze_connection_lifecycle(self, pcap_file: str) -> List[TextContent]:
        """Analyze complete connection lifecycle from SYN to FIN/RST including TLS handshake."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tcp.flags.syn eq 1 or tcp.flags.fin eq 1 or tcp.flags.reset eq 1 or tls.handshake',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tcp.flags',
                '-e',
                'tls.handshake.type',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'connection_lifecycle',
                'lifecycle_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing connection lifecycle: {str(e)}')
            ]

    async def _extract_tls_cipher_analysis(self, pcap_file: str) -> List[TextContent]:
        """Analyze TLS cipher suite negotiations, key exchange groups, and PQC usage."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tls.handshake.ciphersuite',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tls.handshake.ciphersuite',
                '-e',
                'tls.handshake.extensions_supported_group',
                '-e',
                'tls.handshake.ciphersuite',
            ]

            output = await self._run_tshark_command(args)

            # Map known PQC group IDs
            PQC_GROUP_NAMES = {
                '25497': 'X25519Kyber768Draft00',
                '17800': 'X25519MLKEM768',
                '25600': 'SecP256r1MLKEM768',
                '25601': 'X25519MLKEM768',
                '512': 'MLKEM512',
                '513': 'MLKEM768',
                '514': 'MLKEM1024',
                '12107': 'SecP256r1Kyber768',
                '12108': 'SecP384r1Kyber1024',
            }

            cipher_data = []
            pqc_connections = 0
            total_entries = 0

            if output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split('\t')
                    total_entries += 1
                    entry = {
                        'time': parts[0] if len(parts) > 0 else '',
                        'src': parts[1] if len(parts) > 1 else '',
                        'dst': parts[2] if len(parts) > 2 else '',
                        'cipher_suite': parts[3] if len(parts) > 3 else '',
                        'supported_groups': parts[4] if len(parts) > 4 else '',
                        'negotiated_cipher': parts[5] if len(parts) > 5 else '',
                    }
                    # Identify PQC key exchange
                    key_group = entry['supported_groups'].strip()
                    if key_group in PQC_GROUP_NAMES:
                        entry['pqc_algorithm'] = PQC_GROUP_NAMES[key_group]
                        pqc_connections += 1
                    elif entry['supported_groups']:
                        for g in entry['supported_groups'].split(','):
                            if g.strip() in PQC_GROUP_NAMES:
                                entry['pqc_offered'] = PQC_GROUP_NAMES[g.strip()]
                                break
                    cipher_data.append(entry)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tls_cipher_analysis',
                'total_entries': total_entries,
                'pqc_negotiated_connections': pqc_connections,
                'cipher_data': cipher_data[:200],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing TLS cipher suites: {str(e)}')]

    # TCP Analysis Methods
    async def _analyze_tcp_retransmissions(self, pcap_file: str) -> List[TextContent]:
        """Analyze TCP retransmissions and packet loss patterns."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tcp.analysis.retransmission',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tcp.seq',
                '-e',
                'tcp.analysis.retransmission',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tcp_retransmissions',
                'retransmission_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing TCP retransmissions: {str(e)}')
            ]

    async def _analyze_tcp_zero_window(self, pcap_file: str) -> List[TextContent]:
        """Analyze TCP zero window conditions and flow control issues."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tcp.window_size eq 0',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tcp.window_size',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tcp_zero_window',
                'zero_window_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing TCP zero window: {str(e)}')]

    async def _analyze_tcp_window_scaling(self, pcap_file: str) -> List[TextContent]:
        """Analyze TCP window scaling and flow control mechanisms."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tcp.options.wscale',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tcp.options.wscale',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tcp_window_scaling',
                'window_scaling_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing TCP window scaling: {str(e)}')]

    async def _analyze_packet_timing_issues(self, pcap_file: str) -> List[TextContent]:
        """Analyze packet timing issues including out-of-order and duplicate packets."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'tcp.analysis.out_of_order or tcp.analysis.duplicate_ack',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tcp.analysis.out_of_order',
                '-e',
                'tcp.analysis.duplicate_ack',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'packet_timing_issues',
                'timing_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing packet timing issues: {str(e)}')
            ]

    async def _analyze_congestion_indicators(self, pcap_file: str) -> List[TextContent]:
        """Analyze network congestion indicators and quality metrics."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', 'expert']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'congestion_indicators',
                'congestion_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing congestion indicators: {str(e)}')
            ]

    # Advanced Analysis Methods
    async def _analyze_dns_resolution_issues(self, pcap_file: str) -> List[TextContent]:
        """Analyze DNS resolution issues and query patterns."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                'dns',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'dns.qry.name',
                '-e',
                'dns.resp.name',
                '-e',
                'dns.flags.rcode',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'dns_resolution_issues',
                'dns_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing DNS resolution issues: {str(e)}')
            ]

    async def _analyze_expert_information(
        self, pcap_file: str, severity_filter: Optional[str] = None
    ) -> List[TextContent]:
        """Analyze Wireshark expert information for network issues."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', 'expert']
            if severity_filter:
                args.extend(['-z', f'expert,{severity_filter}'])

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'expert_information',
                'severity_filter': severity_filter,
                'expert_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing expert information: {str(e)}')]

    async def _analyze_protocol_anomalies(self, pcap_file: str) -> List[TextContent]:
        """Analyze protocol anomalies and malformed packets."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r',
                pcap_path,
                '-Y',
                '_ws.malformed',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                '_ws.malformed',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'protocol_anomalies',
                'anomaly_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing protocol anomalies: {str(e)}')]

    async def _analyze_network_topology(self, pcap_file: str) -> List[TextContent]:
        """Analyze network topology and routing information."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', 'endpoints,ip', '-z', 'conv,ip']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'network_topology',
                'topology_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing network topology: {str(e)}')]

    async def _analyze_security_threats(self, pcap_file: str) -> List[TextContent]:
        """Analyze potential security threats and suspicious activities."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Look for common security indicators
            args = [
                '-r',
                pcap_path,
                '-Y',
                'tcp.flags.reset eq 1 or icmp.type eq 3 or tcp.analysis.retransmission',
                '-T',
                'fields',
                '-e',
                'frame.time',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
                '-e',
                'tcp.flags.reset',
                '-e',
                'icmp.type',
                '-e',
                'tcp.analysis.retransmission',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'security_threats',
                'threat_indicators': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing security threats: {str(e)}')]

    # Performance & Quality Metrics
    async def _generate_throughput_io_graph(
        self, pcap_file: str, time_interval: int = 1
    ) -> List[TextContent]:
        """Generate throughput I/O graph data with specified time intervals."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', f'io,stat,{time_interval},BYTES']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'throughput_io_graph',
                'time_interval': time_interval,
                'io_graph_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error generating throughput I/O graph: {str(e)}')
            ]

    async def _analyze_bandwidth_utilization(
        self, pcap_file: str, time_window: int = 10
    ) -> List[TextContent]:
        """Analyze bandwidth utilization and traffic patterns."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', f'io,stat,{time_window},BYTES,FRAMES']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'bandwidth_utilization',
                'time_window': time_window,
                'bandwidth_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing bandwidth utilization: {str(e)}')
            ]

    async def _analyze_application_response_times(
        self, pcap_file: str, protocol: str = 'http'
    ) -> List[TextContent]:
        """Analyze application layer response times and performance."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            if protocol.lower() == 'http':
                filter_expr = 'http'
            elif protocol.lower() == 'https':
                filter_expr = 'tls'
            elif protocol.lower() == 'dns':
                filter_expr = 'dns'
            else:
                filter_expr = protocol

            args = [
                '-r',
                pcap_path,
                '-Y',
                filter_expr,
                '-T',
                'fields',
                '-e',
                'frame.time_relative',
                '-e',
                'ip.src',
                '-e',
                'ip.dst',
            ]

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'application_response_times',
                'protocol': protocol,
                'response_data': output.strip().split('\n') if output.strip() else [],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(
                    type='text', text=f'Error analyzing application response times: {str(e)}'
                )
            ]

    async def _analyze_network_quality_metrics(self, pcap_file: str) -> List[TextContent]:
        """Analyze network quality metrics including jitter, packet loss, and error rates."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = ['-r', pcap_path, '-q', '-z', 'expert', '-z', 'rtp,streams']

            output = await self._run_tshark_command(args)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'network_quality_metrics',
                'quality_data': output,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [
                TextContent(type='text', text=f'Error analyzing network quality metrics: {str(e)}')
            ]



    async def _analyze_mtu_fragmentation(self, pcap_file: str) -> List[TextContent]:
        """Analyze MTU/fragmentation issues."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Get fragmented IP packets
            frag_args = [
                '-r', pcap_path,
                '-Y', 'ip.flags.mf == 1 or ip.frag_offset > 0',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'ip.len',
                '-e', 'ip.flags.mf',
                '-e', 'ip.frag_offset',
                '-e', 'ip.id',
            ]
            frag_output = await self._run_tshark_command(frag_args)

            # Get ICMP "need fragmentation" / "packet too big" messages
            icmp_frag_args = [
                '-r', pcap_path,
                '-Y', 'icmp.type == 3 and icmp.code == 4',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'icmp.mtu',
            ]
            icmp_output = await self._run_tshark_command(icmp_frag_args)

            # Get ICMPv6 Packet Too Big
            icmpv6_args = [
                '-r', pcap_path,
                '-Y', 'icmpv6.type == 2',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ipv6.src',
                '-e', 'ipv6.dst',
                '-e', 'icmpv6.mtu',
            ]
            icmpv6_output = await self._run_tshark_command(icmpv6_args)

            # Get DF-bit set packets (PMTUD participants)
            df_args = [
                '-r', pcap_path,
                '-Y', 'ip.flags.df == 1',
                '-T', 'fields',
                '-e', 'ip.len',
            ]
            df_output = await self._run_tshark_command(df_args)

            # Parse results
            fragments = []
            if frag_output.strip():
                for line in frag_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        fragments.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'length': parts[4],
                            'more_fragments': parts[5],
                            'frag_offset': parts[6],
                            'ip_id': parts[7] if len(parts) > 7 else '',
                        })

            pmtud_failures = []
            if icmp_output.strip():
                for line in icmp_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        pmtud_failures.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'suggested_mtu': parts[4] if len(parts) > 4 else 'unknown',
                        })

            if icmpv6_output.strip():
                for line in icmpv6_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        pmtud_failures.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'suggested_mtu': parts[4] if len(parts) > 4 else 'unknown',
                            'protocol': 'ICMPv6',
                        })

            # Analyze DF-bit packet sizes
            max_packet_size = 0
            df_count = 0
            if df_output.strip():
                for line in df_output.strip().split('\n'):
                    try:
                        size = int(line.strip())
                        df_count += 1
                        if size > max_packet_size:
                            max_packet_size = size
                    except ValueError:
                        pass

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'mtu_fragmentation',
                'summary': {
                    'fragmented_packets': len(fragments),
                    'pmtud_failure_messages': len(pmtud_failures),
                    'df_bit_set_packets': df_count,
                    'max_packet_size_with_df': max_packet_size,
                },
                'fragmented_packets': fragments[:100],
                'pmtud_failures': pmtud_failures[:50],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing MTU/fragmentation: {str(e)}')]

    async def _analyze_tcp_resets(self, pcap_file: str) -> List[TextContent]:
        """Analyze TCP RST packets with connection context."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r', pcap_path,
                '-Y', 'tcp.flags.reset == 1',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'tcp.stream',
                '-e', 'tcp.flags.ack',
                '-e', 'tcp.len',
            ]
            output = await self._run_tshark_command(args)

            # Also get SYN packets to identify immediate resets (connection refused)
            syn_args = [
                '-r', pcap_path,
                '-Y', 'tcp.flags.syn == 1 and tcp.flags.ack == 0',
                '-T', 'fields',
                '-e', 'tcp.stream',
                '-e', 'ip.dst',
                '-e', 'tcp.dstport',
            ]
            syn_output = await self._run_tshark_command(syn_args)

            syn_streams = set()
            if syn_output.strip():
                for line in syn_output.strip().split('\n'):
                    parts = line.split('\t')
                    if parts[0]:
                        syn_streams.add(parts[0])

            resets = []
            immediate_resets = 0
            if output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        stream = parts[6]
                        entry = {
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'src_port': parts[4],
                            'dst_port': parts[5],
                            'stream': stream,
                            'ack_set': parts[7] if len(parts) > 7 else '',
                        }
                        # Check if this is a RST to a SYN (connection refused)
                        if stream in syn_streams:
                            entry['likely_cause'] = 'connection_refused'
                            immediate_resets += 1
                        resets.append(entry)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tcp_resets',
                'summary': {
                    'total_resets': len(resets),
                    'connection_refused': immediate_resets,
                    'mid_connection_resets': len(resets) - immediate_resets,
                },
                'resets': resets[:200],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing TCP resets: {str(e)}')]

    async def _analyze_duplicate_acks(self, pcap_file: str) -> List[TextContent]:
        """Analyze duplicate ACKs and fast retransmit patterns."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Get duplicate ACKs
            dup_ack_args = [
                '-r', pcap_path,
                '-Y', 'tcp.analysis.duplicate_ack',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.stream',
                '-e', 'tcp.analysis.duplicate_ack_num',
                '-e', 'tcp.ack',
            ]
            dup_output = await self._run_tshark_command(dup_ack_args)

            # Get fast retransmissions
            fast_retrans_args = [
                '-r', pcap_path,
                '-Y', 'tcp.analysis.fast_retransmission',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.stream',
                '-e', 'tcp.seq',
            ]
            fast_output = await self._run_tshark_command(fast_retrans_args)

            dup_acks = []
            streams_with_dup_acks = set()
            if dup_output.strip():
                for line in dup_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        streams_with_dup_acks.add(parts[4])
                        dup_acks.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'stream': parts[4],
                            'dup_ack_num': parts[5] if len(parts) > 5 else '',
                            'ack_number': parts[6] if len(parts) > 6 else '',
                        })

            fast_retransmits = []
            if fast_output.strip():
                for line in fast_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        fast_retransmits.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'stream': parts[4],
                            'seq': parts[5] if len(parts) > 5 else '',
                        })

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'duplicate_acks',
                'summary': {
                    'total_duplicate_acks': len(dup_acks),
                    'streams_affected': len(streams_with_dup_acks),
                    'fast_retransmissions_triggered': len(fast_retransmits),
                },
                'duplicate_acks': dup_acks[:200],
                'fast_retransmissions': fast_retransmits[:100],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing duplicate ACKs: {str(e)}')]

    async def _analyze_icmp_errors(self, pcap_file: str) -> List[TextContent]:
        """Analyze ICMP error messages."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # ICMP errors (type 3=unreachable, 4=source quench, 5=redirect, 11=TTL exceeded, 12=parameter problem)
            args = [
                '-r', pcap_path,
                '-Y', 'icmp.type == 3 or icmp.type == 4 or icmp.type == 5 or icmp.type == 11 or icmp.type == 12',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'icmp.type',
                '-e', 'icmp.code',
            ]
            output = await self._run_tshark_command(args)

            ICMP_TYPES = {
                '3': 'Destination Unreachable',
                '4': 'Source Quench',
                '5': 'Redirect',
                '11': 'Time Exceeded (TTL)',
                '12': 'Parameter Problem',
            }
            ICMP_UNREACH_CODES = {
                '0': 'Network Unreachable',
                '1': 'Host Unreachable',
                '2': 'Protocol Unreachable',
                '3': 'Port Unreachable',
                '4': 'Fragmentation Needed (DF set)',
                '5': 'Source Route Failed',
                '6': 'Destination Network Unknown',
                '7': 'Destination Host Unknown',
                '9': 'Network Administratively Prohibited',
                '10': 'Host Administratively Prohibited',
                '13': 'Communication Administratively Prohibited',
            }

            errors = []
            type_counts = {}
            if output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        icmp_type = parts[4]
                        icmp_code = parts[5] if len(parts) > 5 else '0'
                        type_name = ICMP_TYPES.get(icmp_type, f'Type {icmp_type}')
                        type_counts[type_name] = type_counts.get(type_name, 0) + 1

                        entry = {
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'type': type_name,
                            'code': icmp_code,
                        }
                        if icmp_type == '3':
                            entry['reason'] = ICMP_UNREACH_CODES.get(icmp_code, f'Code {icmp_code}')
                        errors.append(entry)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'icmp_errors',
                'summary': {
                    'total_icmp_errors': len(errors),
                    'by_type': type_counts,
                },
                'errors': errors[:200],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing ICMP errors: {str(e)}')]

    async def _analyze_connection_timeouts(self, pcap_file: str) -> List[TextContent]:
        """Detect connection timeouts: unanswered SYNs and idle connections."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Find SYN packets without corresponding SYN-ACK (unanswered SYNs)
            syn_args = [
                '-r', pcap_path,
                '-Y', 'tcp.flags.syn == 1 and tcp.flags.ack == 0',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.dstport',
                '-e', 'tcp.stream',
            ]
            syn_output = await self._run_tshark_command(syn_args)

            # Find SYN-ACK packets
            synack_args = [
                '-r', pcap_path,
                '-Y', 'tcp.flags.syn == 1 and tcp.flags.ack == 1',
                '-T', 'fields',
                '-e', 'tcp.stream',
            ]
            synack_output = await self._run_tshark_command(synack_args)

            # Find TCP retransmitted SYNs (strong timeout indicator)
            syn_retrans_args = [
                '-r', pcap_path,
                '-Y', 'tcp.analysis.retransmission and tcp.flags.syn == 1',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.dstport',
                '-e', 'tcp.stream',
            ]
            syn_retrans_output = await self._run_tshark_command(syn_retrans_args)

            # Find TCP keep-alive packets (indicator of idle connections)
            keepalive_args = [
                '-r', pcap_path,
                '-Y', 'tcp.analysis.keep_alive',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.stream',
            ]
            keepalive_output = await self._run_tshark_command(keepalive_args)

            # Build set of streams that got SYN-ACK
            answered_streams = set()
            if synack_output.strip():
                for line in synack_output.strip().split('\n'):
                    answered_streams.add(line.strip())

            # Find unanswered SYNs
            unanswered_syns = []
            if syn_output.strip():
                for line in syn_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 6:
                        stream = parts[5]
                        if stream not in answered_streams:
                            unanswered_syns.append({
                                'frame': parts[0],
                                'time': parts[1],
                                'src': parts[2],
                                'dst': parts[3],
                                'dst_port': parts[4],
                                'stream': stream,
                            })

            # SYN retransmissions (definite timeout indicators)
            syn_retransmissions = []
            retrans_streams = set()
            if syn_retrans_output.strip():
                for line in syn_retrans_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 6:
                        retrans_streams.add(parts[5])
                        syn_retransmissions.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'dst_port': parts[4],
                            'stream': parts[5],
                        })

            keepalive_count = len(keepalive_output.strip().split('\n')) if keepalive_output.strip() else 0

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'connection_timeouts',
                'summary': {
                    'unanswered_syns': len(unanswered_syns),
                    'syn_retransmissions': len(syn_retransmissions),
                    'streams_with_syn_retrans': len(retrans_streams),
                    'keepalive_packets': keepalive_count,
                },
                'unanswered_connections': unanswered_syns[:100],
                'syn_retransmissions': syn_retransmissions[:100],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing connection timeouts: {str(e)}')]

    async def _analyze_out_of_order_packets(self, pcap_file: str) -> List[TextContent]:
        """Detect TCP out-of-order packets."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r', pcap_path,
                '-Y', 'tcp.analysis.out_of_order',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'tcp.stream',
                '-e', 'tcp.seq',
                '-e', 'tcp.len',
            ]
            output = await self._run_tshark_command(args)

            ooo_packets = []
            streams_affected = set()
            if output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        streams_affected.add(parts[6])
                        ooo_packets.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'src_port': parts[4],
                            'dst_port': parts[5],
                            'stream': parts[6],
                            'seq': parts[7] if len(parts) > 7 else '',
                            'length': parts[8] if len(parts) > 8 else '',
                        })

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'out_of_order_packets',
                'summary': {
                    'total_out_of_order': len(ooo_packets),
                    'streams_affected': len(streams_affected),
                },
                'out_of_order_packets': ooo_packets[:200],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing out-of-order packets: {str(e)}')]

    async def _analyze_quic_traffic(self, pcap_file: str) -> List[TextContent]:
        """Analyze QUIC/HTTP3 traffic patterns."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Get QUIC connection summary
            quic_args = [
                '-r', pcap_path,
                '-Y', 'quic',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'quic.connection.number',
                '-e', 'quic.long.packet_type',
                '-e', 'quic.version',
                '-e', 'quic.frame_type',
            ]
            quic_output = await self._run_tshark_command(quic_args)

            # Get QUIC handshake (Initial packets)
            handshake_args = [
                '-r', pcap_path,
                '-Y', 'quic.long.packet_type == 0',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'udp.dstport',
                '-e', 'quic.version',
            ]
            handshake_output = await self._run_tshark_command(handshake_args)

            # Get QUIC connection close frames
            close_args = [
                '-r', pcap_path,
                '-Y', 'quic.frame_type == 0x1c or quic.frame_type == 0x1d',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'quic.cc.error_code',
                '-e', 'quic.cc.reason_phrase',
            ]
            close_output = await self._run_tshark_command(close_args)

            # Get QUIC retry packets (version negotiation issues)
            retry_args = [
                '-r', pcap_path,
                '-Y', 'quic.long.packet_type == 3',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'ip.src',
                '-e', 'ip.dst',
            ]
            retry_output = await self._run_tshark_command(retry_args)

            # Parse QUIC packets
            total_quic = 0
            connections = set()
            versions = set()
            packet_types = {}

            if quic_output.strip():
                for line in quic_output.strip().split('\n'):
                    parts = line.split('\t')
                    total_quic += 1
                    if len(parts) > 6 and parts[6]:
                        connections.add(parts[6])
                    if len(parts) > 8 and parts[8]:
                        versions.add(parts[8])
                    if len(parts) > 7 and parts[7]:
                        ptype = parts[7]
                        packet_types[ptype] = packet_types.get(ptype, 0) + 1

            # Parse handshakes
            handshakes = []
            if handshake_output.strip():
                for line in handshake_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        handshakes.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'dst_port': parts[4] if len(parts) > 4 else '',
                            'version': parts[5] if len(parts) > 5 else '',
                        })

            # Parse connection closes
            conn_closes = []
            if close_output.strip():
                for line in close_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        conn_closes.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'error_code': parts[4] if len(parts) > 4 else '',
                            'reason': parts[5] if len(parts) > 5 else '',
                        })

            retry_count = len(retry_output.strip().split('\n')) if retry_output.strip() else 0

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'quic_http3',
                'summary': {
                    'total_quic_packets': total_quic,
                    'unique_connections': len(connections),
                    'quic_versions_seen': list(versions),
                    'packet_type_distribution': packet_types,
                    'initial_handshakes': len(handshakes),
                    'connection_closes': len(conn_closes),
                    'retry_packets': retry_count,
                },
                'handshakes': handshakes[:50],
                'connection_closes': conn_closes[:50],
            }

            if total_quic == 0:
                result['note'] = 'No QUIC traffic detected. Traffic may be using TCP/TLS instead of QUIC/HTTP3.'

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing QUIC traffic: {str(e)}')]

    async def _analyze_connection_reuse(self, pcap_file: str) -> List[TextContent]:
        """Analyze HTTP connection pooling and keep-alive reuse."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Get HTTP requests with their TCP stream numbers
            http_req_args = [
                '-r', pcap_path,
                '-Y', 'http.request',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'tcp.stream',
                '-e', 'http.host',
                '-e', 'http.request.method',
                '-e', 'http.request.uri',
                '-e', 'http.connection',
            ]
            http_output = await self._run_tshark_command(http_req_args)

            # Get TCP stream durations (SYN to FIN/RST)
            stream_args = [
                '-r', pcap_path,
                '-Y', 'tcp.flags.syn == 1 and tcp.flags.ack == 0',
                '-T', 'fields',
                '-e', 'tcp.stream',
                '-e', 'frame.time_epoch',
                '-e', 'ip.dst',
                '-e', 'tcp.dstport',
            ]
            stream_output = await self._run_tshark_command(stream_args)

            # Get FIN packets to calculate connection duration
            fin_args = [
                '-r', pcap_path,
                '-Y', 'tcp.flags.fin == 1',
                '-T', 'fields',
                '-e', 'tcp.stream',
                '-e', 'frame.time_epoch',
            ]
            fin_output = await self._run_tshark_command(fin_args)

            # Parse HTTP requests per stream
            stream_requests = {}
            total_requests = 0
            if http_output.strip():
                for line in http_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        total_requests += 1
                        stream = parts[2]
                        if stream not in stream_requests:
                            stream_requests[stream] = {
                                'requests': 0,
                                'host': parts[3] if len(parts) > 3 else '',
                                'methods': [],
                            }
                        stream_requests[stream]['requests'] += 1
                        if len(parts) > 4:
                            stream_requests[stream]['methods'].append(parts[4])

            # Parse stream start times
            stream_starts = {}
            if stream_output.strip():
                for line in stream_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 2 and parts[0]:
                        stream_starts[parts[0]] = {
                            'start_epoch': parts[1],
                            'dst': parts[2] if len(parts) > 2 else '',
                            'dst_port': parts[3] if len(parts) > 3 else '',
                        }

            # Parse FIN times
            stream_ends = {}
            if fin_output.strip():
                for line in fin_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 2 and parts[0]:
                        stream_ends[parts[0]] = parts[1]

            # Calculate metrics
            total_streams = len(stream_starts)
            streams_with_requests = len(stream_requests)
            single_use = sum(1 for s in stream_requests.values() if s['requests'] == 1)
            multi_use = sum(1 for s in stream_requests.values() if s['requests'] > 1)

            reuse_details = []
            for stream_id, data in sorted(stream_requests.items(), key=lambda x: x[1]['requests'], reverse=True)[:30]:
                entry = {
                    'stream': stream_id,
                    'requests': data['requests'],
                    'host': data['host'],
                }
                if stream_id in stream_starts and stream_id in stream_ends:
                    try:
                        duration = float(stream_ends[stream_id]) - float(stream_starts[stream_id]['start_epoch'])
                        entry['duration_seconds'] = round(duration, 2)
                    except (ValueError, TypeError):
                        pass
                reuse_details.append(entry)

            avg_requests_per_conn = (
                total_requests / streams_with_requests if streams_with_requests > 0 else 0
            )

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'connection_reuse',
                'summary': {
                    'total_http_requests': total_requests,
                    'total_tcp_connections': total_streams,
                    'connections_with_http': streams_with_requests,
                    'single_request_connections': single_use,
                    'multi_request_connections': multi_use,
                    'avg_requests_per_connection': round(avg_requests_per_conn, 1),
                    'connection_reuse_rate': f'{(multi_use / streams_with_requests * 100):.1f}%' if streams_with_requests > 0 else '0%',
                },
                'top_reused_connections': reuse_details,
            }

            if avg_requests_per_conn < 2 and total_requests > 5:
                result['recommendation'] = 'Low connection reuse detected. Ensure HTTP keep-alive is enabled and connection pool settings are adequate.'

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing connection reuse: {str(e)}')]

    async def _analyze_geo_asn_mapping(self, pcap_file: str, top_n: int = 20) -> List[TextContent]:
        """Map top IPs to ASN/organization using whois."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Get top talkers by packet count
            args = [
                '-r', pcap_path,
                '-T', 'fields',
                '-e', 'ip.src',
                '-e', 'ip.dst',
            ]
            output = await self._run_tshark_command(args)

            # Count packets per IP
            ip_counts = {}
            if output.strip():
                for line in output.strip().split('\n'):
                    parts = line.split('\t')
                    for ip in parts:
                        ip = ip.strip()
                        if ip and not ip.startswith('10.') and not ip.startswith('172.') and not ip.startswith('192.168.') and not ip.startswith('127.'):
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1

            # Sort by count and take top N
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

            # Resolve ASN for each IP using whois
            ip_mappings = []
            for ip, count in top_ips:
                asn_info = await self._lookup_asn(ip)
                ip_mappings.append({
                    'ip': ip,
                    'packets': count,
                    'asn': asn_info.get('asn', 'unknown'),
                    'organization': asn_info.get('org', 'unknown'),
                    'description': asn_info.get('desc', ''),
                })

            # Group by organization
            org_traffic = {}
            for entry in ip_mappings:
                org = entry['organization']
                if org not in org_traffic:
                    org_traffic[org] = {'packets': 0, 'ips': []}
                org_traffic[org]['packets'] += entry['packets']
                org_traffic[org]['ips'].append(entry['ip'])

            org_summary = sorted(
                [{'organization': k, 'total_packets': v['packets'], 'ip_count': len(v['ips'])}
                 for k, v in org_traffic.items()],
                key=lambda x: x['total_packets'],
                reverse=True
            )

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'geo_asn_mapping',
                'summary': {
                    'public_ips_analyzed': len(top_ips),
                    'unique_organizations': len(org_traffic),
                },
                'ip_mappings': ip_mappings,
                'traffic_by_organization': org_summary[:20],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error analyzing geo/ASN mapping: {str(e)}')]

    async def _lookup_asn(self, ip: str) -> Dict[str, str]:
        """Look up ASN info for an IP using whois."""
        try:
            cmd = ['whois', '-h', 'whois.radb.net', ip]
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=5)
            output = stdout.decode()

            asn = ''
            org = ''
            desc = ''
            for line in output.split('\n'):
                line_lower = line.lower()
                if line_lower.startswith('origin:'):
                    asn = line.split(':', 1)[1].strip()
                elif line_lower.startswith('descr:') and not desc:
                    desc = line.split(':', 1)[1].strip()
                    org = desc
                elif line_lower.startswith('netname:') and not org:
                    org = line.split(':', 1)[1].strip()

            return {'asn': asn, 'org': org, 'desc': desc}
        except Exception:
            return {'asn': 'lookup_failed', 'org': 'lookup_failed', 'desc': ''}

    async def _follow_tcp_stream(self, pcap_file: str, stream_index: int) -> List[TextContent]:
        """Reassemble and follow a TCP stream."""
        try:
            if not isinstance(stream_index, int) or stream_index < 0:
                raise ValueError('stream_index must be a non-negative integer')
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r', pcap_path,
                '-z', f'follow,tcp,ascii,{stream_index}',
                '-q',
            ]
            output = await self._run_tshark_command(args)

            # Get stream metadata
            meta_args = [
                '-r', pcap_path,
                '-Y', f'tcp.stream == {stream_index}',
                '-T', 'fields',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-c', '1',
            ]
            meta_output = await self._run_tshark_command(meta_args)

            metadata = {}
            if meta_output.strip():
                parts = meta_output.strip().split('\n')[0].split('\t')
                if len(parts) >= 4:
                    metadata = {
                        'client': f'{parts[0]}:{parts[2]}',
                        'server': f'{parts[1]}:{parts[3]}',
                    }

            # Count packets in stream
            count_args = [
                '-r', pcap_path,
                '-Y', f'tcp.stream == {stream_index}',
                '-T', 'fields',
                '-e', 'frame.number',
            ]
            count_output = await self._run_tshark_command(count_args)
            packet_count = len(count_output.strip().split('\n')) if count_output.strip() else 0

            # Truncate output if too large
            stream_data = output[:50000] if len(output) > 50000 else output
            truncated = len(output) > 50000

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'tcp_stream_follow',
                'stream_index': stream_index,
                'metadata': metadata,
                'packet_count': packet_count,
                'truncated': truncated,
                'stream_data': stream_data,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error following TCP stream: {str(e)}')]

    async def _follow_udp_stream(self, pcap_file: str, stream_index: int) -> List[TextContent]:
        """Reassemble and follow a UDP stream."""
        try:
            if not isinstance(stream_index, int) or stream_index < 0:
                raise ValueError('stream_index must be a non-negative integer')
            pcap_path = self._resolve_pcap_path(pcap_file)

            args = [
                '-r', pcap_path,
                '-z', f'follow,udp,ascii,{stream_index}',
                '-q',
            ]
            output = await self._run_tshark_command(args)

            # Get stream metadata
            meta_args = [
                '-r', pcap_path,
                '-Y', f'udp.stream == {stream_index}',
                '-T', 'fields',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-c', '1',
            ]
            meta_output = await self._run_tshark_command(meta_args)

            metadata = {}
            if meta_output.strip():
                parts = meta_output.strip().split('\n')[0].split('\t')
                if len(parts) >= 4:
                    metadata = {
                        'src': f'{parts[0]}:{parts[2]}',
                        'dst': f'{parts[1]}:{parts[3]}',
                    }

            stream_data = output[:50000] if len(output) > 50000 else output
            truncated = len(output) > 50000

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'udp_stream_follow',
                'stream_index': stream_index,
                'metadata': metadata,
                'truncated': truncated,
                'stream_data': stream_data,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error following UDP stream: {str(e)}')]

    async def _extract_fields(self, pcap_file: str, fields: List[str], display_filter: str = '', limit: int = 100) -> List[TextContent]:
        """Extract arbitrary tshark fields from packets."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Validate field names (only allow safe characters)
            import string
            allowed_field_chars = string.ascii_letters + string.digits + '._'
            for field in fields:
                if not all(c in allowed_field_chars for c in field):
                    raise ValueError(f'Invalid field name: {field}')

            args = ['-r', pcap_path, '-T', 'fields']

            if display_filter:
                args.extend(['-Y', display_filter])

            for field in fields:
                args.extend(['-e', field])

            args.extend(['-c', str(limit)])

            output = await self._run_tshark_command(args)

            rows = []
            if output.strip():
                for line in output.strip().split('\n'):
                    values = line.split('\t')
                    row = {}
                    for i, field in enumerate(fields):
                        row[field] = values[i] if i < len(values) else ''
                    rows.append(row)

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'field_extraction',
                'fields_requested': fields,
                'display_filter': display_filter or 'none',
                'total_rows': len(rows),
                'data': rows,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error extracting fields: {str(e)}')]

    async def _detect_arp_spoofing(self, pcap_file: str) -> List[TextContent]:
        """Detect ARP spoofing indicators."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Get all ARP replies
            arp_args = [
                '-r', pcap_path,
                '-Y', 'arp.opcode == 2',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'arp.src.hw_mac',
                '-e', 'arp.src.proto_ipv4',
                '-e', 'eth.src',
            ]
            arp_output = await self._run_tshark_command(arp_args)

            # Get gratuitous ARPs
            grat_args = [
                '-r', pcap_path,
                '-Y', 'arp.isgratuitous == 1',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'arp.src.hw_mac',
                '-e', 'arp.src.proto_ipv4',
            ]
            grat_output = await self._run_tshark_command(grat_args)

            # Build IP-to-MAC mapping to detect conflicts
            ip_mac_map = {}
            arp_replies = []
            if arp_output.strip():
                for line in arp_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        mac = parts[2]
                        ip = parts[3]
                        if ip:
                            if ip not in ip_mac_map:
                                ip_mac_map[ip] = set()
                            ip_mac_map[ip].add(mac)
                        arp_replies.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'mac': mac,
                            'ip': ip,
                        })

            # Detect IP addresses with multiple MACs (spoofing indicator)
            conflicts = []
            for ip, macs in ip_mac_map.items():
                if len(macs) > 1:
                    conflicts.append({
                        'ip': ip,
                        'mac_addresses': list(macs),
                        'severity': 'HIGH - possible ARP spoofing',
                    })

            # Count gratuitous ARPs per source
            grat_counts = {}
            grat_total = 0
            if grat_output.strip():
                for line in grat_output.strip().split('\n'):
                    parts = line.split('\t')
                    grat_total += 1
                    if len(parts) >= 4:
                        mac = parts[2]
                        grat_counts[mac] = grat_counts.get(mac, 0) + 1

            # Flag excessive gratuitous ARPs
            grat_floods = [
                {'mac': mac, 'count': count, 'severity': 'MEDIUM - gratuitous ARP flood'}
                for mac, count in grat_counts.items() if count > 10
            ]

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'arp_spoofing_detection',
                'summary': {
                    'total_arp_replies': len(arp_replies),
                    'gratuitous_arps': grat_total,
                    'ip_mac_conflicts': len(conflicts),
                    'gratuitous_floods': len(grat_floods),
                    'spoofing_detected': len(conflicts) > 0,
                },
                'ip_mac_conflicts': conflicts,
                'gratuitous_arp_floods': grat_floods,
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error detecting ARP spoofing: {str(e)}')]

    async def _detect_dns_tunneling(self, pcap_file: str) -> List[TextContent]:
        """Detect DNS tunneling indicators."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # Get all DNS queries
            dns_args = [
                '-r', pcap_path,
                '-Y', 'dns.qry.name and dns.flags.response == 0',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'dns.qry.name',
                '-e', 'dns.qry.type',
            ]
            dns_output = await self._run_tshark_command(dns_args)

            # Get TXT record queries (commonly used in tunneling)
            txt_args = [
                '-r', pcap_path,
                '-Y', 'dns.qry.type == 16',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'ip.src',
                '-e', 'dns.qry.name',
            ]
            txt_output = await self._run_tshark_command(txt_args)

            # Analyze queries
            long_queries = []
            domain_counts = {}
            src_query_counts = {}
            total_queries = 0

            if dns_output.strip():
                for line in dns_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        total_queries += 1
                        src = parts[2]
                        qname = parts[3]

                        src_query_counts[src] = src_query_counts.get(src, 0) + 1

                        # Extract base domain (last 2 labels)
                        labels = qname.split('.')
                        base_domain = '.'.join(labels[-2:]) if len(labels) >= 2 else qname
                        domain_counts[base_domain] = domain_counts.get(base_domain, 0) + 1

                        # Flag long queries (tunneling indicator)
                        if len(qname) > 50:
                            long_queries.append({
                                'frame': parts[0],
                                'src': src,
                                'query': qname,
                                'length': len(qname),
                            })

            # TXT record analysis
            txt_count = len(txt_output.strip().split('\n')) if txt_output.strip() else 0

            # Identify suspicious patterns
            suspicious_domains = []
            for domain, count in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True):
                if count > 50:
                    suspicious_domains.append({
                        'domain': domain,
                        'query_count': count,
                        'indicator': 'HIGH query volume to single domain',
                    })

            # Flag hosts with excessive queries
            query_floods = [
                {'src': src, 'query_count': count}
                for src, count in src_query_counts.items() if count > 200
            ]

            tunneling_indicators = []
            if len(long_queries) > 5:
                tunneling_indicators.append(f'{len(long_queries)} queries exceed 50 chars (data encoding in subdomain)')
            if txt_count > 20:
                tunneling_indicators.append(f'{txt_count} TXT record queries (common tunneling channel)')
            if suspicious_domains:
                tunneling_indicators.append(f'{len(suspicious_domains)} domains with >50 queries (beaconing)')

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'dns_tunneling_detection',
                'summary': {
                    'total_dns_queries': total_queries,
                    'txt_record_queries': txt_count,
                    'long_queries_over_50_chars': len(long_queries),
                    'tunneling_likelihood': 'HIGH' if len(tunneling_indicators) >= 2 else ('MEDIUM' if tunneling_indicators else 'LOW'),
                },
                'tunneling_indicators': tunneling_indicators,
                'long_queries': long_queries[:50],
                'high_volume_domains': suspicious_domains[:20],
                'query_flood_sources': query_floods[:20],
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error detecting DNS tunneling: {str(e)}')]

    async def _extract_credentials(self, pcap_file: str) -> List[TextContent]:
        """Detect plaintext credentials in traffic."""
        try:
            pcap_path = self._resolve_pcap_path(pcap_file)

            # HTTP Basic Auth
            http_auth_args = [
                '-r', pcap_path,
                '-Y', 'http.authorization',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'http.host',
                '-e', 'http.authorization',
            ]
            http_auth_output = await self._run_tshark_command(http_auth_args)

            # FTP USER/PASS
            ftp_args = [
                '-r', pcap_path,
                '-Y', 'ftp.request.command == USER or ftp.request.command == PASS',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'ftp.request.command',
                '-e', 'ftp.request.arg',
            ]
            ftp_output = await self._run_tshark_command(ftp_args)

            # SMTP AUTH
            smtp_args = [
                '-r', pcap_path,
                '-Y', 'smtp.auth.username or smtp.auth.password',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'smtp.auth.username',
                '-e', 'smtp.auth.password',
            ]
            smtp_output = await self._run_tshark_command(smtp_args)

            # Telnet (look for login/password prompts)
            telnet_args = [
                '-r', pcap_path,
                '-Y', 'telnet',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.stream',
            ]
            telnet_output = await self._run_tshark_command(telnet_args)

            credentials = []

            # Parse HTTP auth
            if http_auth_output.strip():
                for line in http_auth_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        credentials.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'protocol': 'HTTP Basic Auth',
                            'host': parts[4] if len(parts) > 4 else '',
                            'detail': 'Authorization header present (Base64 encoded)',
                        })

            # Parse FTP
            if ftp_output.strip():
                for line in ftp_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        credentials.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'protocol': 'FTP',
                            'command': parts[4] if len(parts) > 4 else '',
                            'detail': f'Plaintext {parts[4]}' if len(parts) > 4 else 'Credential exchange',
                        })

            # Parse SMTP
            if smtp_output.strip():
                for line in smtp_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        credentials.append({
                            'frame': parts[0],
                            'time': parts[1],
                            'src': parts[2],
                            'dst': parts[3],
                            'protocol': 'SMTP AUTH',
                            'detail': 'SMTP authentication credentials detected',
                        })

            # Telnet sessions (flag as potential credential exposure)
            telnet_streams = set()
            if telnet_output.strip():
                for line in telnet_output.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        telnet_streams.add(parts[3])

            result = {
                'pcap_file': pcap_file,
                'analysis_type': 'credential_detection',
                'summary': {
                    'total_credential_exposures': len(credentials),
                    'telnet_sessions': len(telnet_streams),
                    'risk_level': 'HIGH' if credentials else ('MEDIUM' if telnet_streams else 'LOW'),
                },
                'credentials_found': credentials[:100],
                'telnet_sessions_detected': len(telnet_streams),
                'recommendation': 'Plaintext credential protocols detected. Migrate to encrypted alternatives (HTTPS, SFTP, SSH, SMTPS).' if credentials else 'No plaintext credentials detected.',
            }

            return [TextContent(type='text', text=json.dumps(result, indent=2))]
        except Exception as e:
            return [TextContent(type='text', text=f'Error extracting credentials: {str(e)}')]

    async def run(self):
        """Run the PCAP Analyzer MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name='pcap-analyzer-mcp-server',
                    server_version='1.0.0',
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(), experimental_capabilities={}
                    ),
                ),
            )


def main():
    """Run the PCAP Analyzer MCP server."""
    server = PCAPAnalyzerServer()
    asyncio.run(server.run())


if __name__ == '__main__':
    main()
