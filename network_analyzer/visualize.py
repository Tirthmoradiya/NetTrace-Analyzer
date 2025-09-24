"""
Network traffic visualization module.
"""

import time
import logging
import pandas as pd
import plotly.express as px
import json
import networkx as nx
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter

logger = logging.getLogger(__name__)

class RateLimiter:
    """Simple rate limiter for visualization updates."""
    
    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self.last_update = datetime.min
        
    def should_update(self) -> bool:
        """Check if enough time has passed for next update."""
        now = datetime.now()
        if now - self.last_update >= timedelta(seconds=self.min_interval):
            self.last_update = now
            return True
        return False

class NetworkVisualizer:
    """Creates visualizations for network traffic analysis."""
    
    def __init__(self, output_dir: str = "reports", min_update_interval: float = 1.0):
        """Initialize the visualizer with rate limiting."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(min_update_interval)
        
        # Track visualization state
        self.last_error = None
        self.update_count = 0
        self.start_time = time.time()
        
    def _handle_visualization_error(self, viz_type: str, error: Exception) -> None:
        """Handle visualization errors gracefully."""
        self.last_error = error
        logger.error(f"Error creating {viz_type} visualization: {str(error)}")
        
        # Log additional diagnostics
        logger.debug(f"Visualization stats - Updates: {self.update_count}, "
                    f"Runtime: {time.time() - self.start_time:.1f}s")
    
    def create_traffic_flow_graph(self, flows: List[Dict[str, Any]], 
                                output_file: str = "traffic_flow.html") -> None:
        """Create interactive graph of traffic flows."""
        # Create networkx graph
        G = nx.DiGraph()
        
        # Add nodes and edges
        for flow in flows:
            src = flow['source']
            dst = flow['destination']
            G.add_edge(src, dst, 
                      weight=flow.get('bytes', 1),
                      protocol=flow.get('protocol', ''),
                      port=flow.get('port', ''))
        
        # Get positions using spring layout
        pos = nx.spring_layout(G)
        
        # Create plotly figure
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')
        
        node_x = []
        node_y = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=list(G.nodes()),
            textposition="bottom center",
            marker=dict(
                size=10,
                line_width=2))
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace],
                     layout=go.Layout(
                        title='Network Traffic Flow',
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                    )
        
        # Save
        fig.write_html(str(self.output_dir / output_file))
    
    def create_time_series(self, data: List[Dict[str, Any]], 
                          output_file: str = "time_series.html") -> None:
        """Create time series visualizations of network metrics."""
        if not data or len(data) == 0:
            # Create empty plot if no data
            fig = go.Figure()
            fig.add_annotation(text="No time series data available", 
                             xref="paper", yref="paper", x=0.5, y=0.5,
                             showarrow=False, font_size=16)
            fig.update_layout(title_text="Network Traffic Metrics", height=400)
            fig.write_html(str(self.output_dir / output_file))
            return
            
        df = pd.DataFrame(data)
        
        # Check if required columns exist
        required_cols = ['timestamp', 'packets_per_sec', 'bytes_per_sec', 'unique_ips']
        missing_cols = [col for col in required_cols if col not in df.columns]
        
        if missing_cols:
            # Create simple plot with available data
            fig = go.Figure()
            if 'timestamp' in df.columns:
                for col in df.columns:
                    if col != 'timestamp' and df[col].dtype in ['int64', 'float64']:
                        fig.add_trace(go.Scatter(x=df['timestamp'], y=df[col], name=col))
            else:
                fig.add_annotation(text=f"No time series data available. Missing: {', '.join(missing_cols)}", 
                                 xref="paper", yref="paper", x=0.5, y=0.5,
                                 showarrow=False, font_size=16)
            fig.update_layout(title_text="Network Traffic Metrics", height=400)
            fig.write_html(str(self.output_dir / output_file))
            return
        
        # Create subplots
        fig = make_subplots(rows=3, cols=1,
                           subplot_titles=('Packets per Second',
                                         'Bytes per Second',
                                         'Unique IPs'))
        
        # Add traces
        fig.add_trace(
            go.Scatter(x=df['timestamp'], y=df['packets_per_sec'],
                      name="Packets/sec"),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Scatter(x=df['timestamp'], y=df['bytes_per_sec'],
                      name="Bytes/sec"),
            row=2, col=1
        )
        
        fig.add_trace(
            go.Scatter(x=df['timestamp'], y=df['unique_ips'],
                      name="Unique IPs"),
            row=3, col=1
        )
        
        # Update layout
        fig.update_layout(height=900, title_text="Network Traffic Metrics")
        fig.write_html(str(self.output_dir / output_file))
    
    def create_protocol_distribution(self, protocols: Dict[str, int],
                                   output_file: str = "protocols.html") -> None:
        """Create protocol distribution pie chart."""
        if not protocols:
            fig = go.Figure()
            fig.add_annotation(text="No protocol data available", 
                             xref="paper", yref="paper", x=0.5, y=0.5,
                             showarrow=False, font_size=16)
            fig.update_layout(title_text="Protocol Distribution", height=400)
            fig.write_html(str(self.output_dir / output_file))
            return
            
        fig = px.pie(
            values=list(protocols.values()),
            names=list(protocols.keys()),
            title='Protocol Distribution',
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        fig.update_layout(height=500)
        fig.write_html(str(self.output_dir / output_file))
    
    def create_protocol_details(self, protocol_data: Dict[str, Dict], 
                               output_file: str = "protocol_details.html") -> None:
        """Create detailed protocol analysis charts."""
        if not protocol_data:
            fig = go.Figure()
            fig.add_annotation(text="No detailed protocol data available", 
                             xref="paper", yref="paper", x=0.5, y=0.5,
                             showarrow=False, font_size=16)
            fig.update_layout(title_text="Protocol Details", height=400)
            fig.write_html(str(self.output_dir / output_file))
            return
        
        # Create subplots for different protocol metrics
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Packets by Protocol', 'Bytes by Protocol', 
                          'Port Usage', 'Protocol Types'),
            specs=[[{"type": "bar"}, {"type": "bar"}],
                   [{"type": "bar"}, {"type": "bar"}]]
        )
        
        protocols = list(protocol_data.keys())
        packet_counts = [protocol_data[p].get('packets', 0) for p in protocols]
        byte_counts = [protocol_data[p].get('bytes', 0) for p in protocols]
        
        # Packets by protocol
        fig.add_trace(
            go.Bar(x=protocols, y=packet_counts, name="Packets", 
                  marker_color='lightblue'),
            row=1, col=1
        )
        
        # Bytes by protocol
        fig.add_trace(
            go.Bar(x=protocols, y=byte_counts, name="Bytes", 
                  marker_color='lightgreen'),
            row=1, col=2
        )
        
        # Port usage (top 10 ports across all protocols)
        all_ports = []
        for protocol, data in protocol_data.items():
            ports = data.get('ports', [])
            all_ports.extend([(port, protocol) for port in ports])
        
        if all_ports:
            port_counts = Counter([port for port, _ in all_ports])
            top_ports = dict(port_counts.most_common(10))
            
            fig.add_trace(
                go.Bar(x=list(top_ports.keys()), y=list(top_ports.values()), 
                      name="Port Usage", marker_color='orange'),
                row=2, col=1
            )
        
        # ICMP types if available
        icmp_data = protocol_data.get('icmp', {})
        icmp_types = icmp_data.get('type_names', [])
        if icmp_types:
            type_counts = Counter(icmp_types)
            fig.add_trace(
                go.Bar(x=list(type_counts.keys()), y=list(type_counts.values()), 
                      name="ICMP Types", marker_color='red'),
                row=2, col=2
            )
        
        fig.update_layout(height=800, title_text="Detailed Protocol Analysis")
        fig.write_html(str(self.output_dir / output_file))
    
    def create_anomaly_timeline(self, alerts: List[Dict[str, Any]],
                                output_file: str = "anomalies.html") -> None:
        """Create interactive timeline of detected anomalies."""
        if not alerts or len(alerts) == 0:
            # Create empty plot if no alerts
            fig = go.Figure()
            fig.add_annotation(text="No anomaly data available", 
                             xref="paper", yref="paper", x=0.5, y=0.5,
                             showarrow=False, font_size=16)
            fig.update_layout(title_text="Anomaly Timeline", height=400)
            fig.write_html(str(self.output_dir / output_file))
            return
            
        try:
            df = pd.DataFrame(alerts)
            
            # Check if required columns exist
            if 'timestamp' not in df.columns:
                fig = go.Figure()
                fig.add_annotation(text="No timestamp data in alerts", 
                                 xref="paper", yref="paper", x=0.5, y=0.5,
                                 showarrow=False, font_size=16)
                fig.update_layout(title_text="Anomaly Timeline", height=400)
                fig.write_html(str(self.output_dir / output_file))
                return
            
            # Create simple scatter plot if timeline data is not available
            if 'type' not in df.columns or 'severity' not in df.columns:
                fig = go.Figure()
                fig.add_scatter(x=df['timestamp'], y=[1] * len(df), 
                              mode='markers', name='Alerts',
                              text=df.get('reason', 'Alert'),
                              hovertemplate='%{text}<br>Time: %{x}<extra></extra>')
                fig.update_layout(title_text="Anomaly Timeline", height=400)
                fig.write_html(str(self.output_dir / output_file))
                return
            
            # Create a simple scatter plot instead of timeline
            fig = px.scatter(
                df,
                x='timestamp',
                y='type',
                color='severity',
                hover_data=['indicator', 'signature'],
                title='Anomaly Timeline'
            )
            
            fig.update_layout(height=400)
            fig.write_html(str(self.output_dir / output_file))
            
        except Exception as e:
            logger.error(f"Error creating anomaly timeline: {e}")
            # Create fallback plot
            fig = go.Figure()
            fig.add_annotation(text=f"Error creating timeline: {str(e)}", 
                             xref="paper", yref="paper", x=0.5, y=0.5,
                             showarrow=False, font_size=16)
            fig.update_layout(title_text="Anomaly Timeline", height=400)
            fig.write_html(str(self.output_dir / output_file))
    
    def create_interactive_network_map(self, flows: List[Dict[str, Any]],
                                       output_file: str = "interactive_network_map.html") -> None:
        """
        Generates an interactive network map using Cytoscape.js.
        """
        print(f"Received flows for interactive map: {flows[:5]}") # Print first 5 flows for inspection
        # TODO: Implement data transformation for Cytoscape.js and HTML generation

    def generate_report(self, data: Dict[str, Any],
                       output_file: str = "report.html") -> None:
        """Generate comprehensive HTML report."""
        # Create traffic flow graph
        self.create_traffic_flow_graph(data.get('flows', []))

        # Create interactive network map
        self.create_interactive_network_map(data.get('flows', []))

        # Create time series
        self.create_time_series(data.get('metrics', []))

        # Create protocol distribution
        self.create_protocol_distribution(data.get('protocols', {}))

        # Create detailed protocol analysis
        self.create_protocol_details(data.get('protocol_details', {}))

        # Create anomaly timeline
        self.create_anomaly_timeline(data.get('alerts', []))

        # Create deep HTTP analysis report
        self.create_http_analysis_report(data.get('http_requests', []))

        # Create deep DNS analysis report
        self.create_dns_analysis_report(data.get('dns_queries_and_responses', []))

        # Create main report
        html_content = f"""
        <html>
        <head>
            <title>Network Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin: 20px 0; }}
                iframe {{ width: 100%; border: none; }}
            </style>
        </head>
        <body>
            <h1>Network Analysis Report</h1>
            <div class="section">
                <h2>Traffic Flow</h2>
                <iframe src="traffic_flow.html" height="600px"></iframe>
            </div>
            <div class="section">
                <h2>Interactive Network Map</h2>
                <iframe src="interactive_network_map.html" height="600px"></iframe>
            </div>
            <div class="section">
                <h2>Traffic Metrics</h2>
                <iframe src="time_series.html" height="900px"></iframe>
            </div>
            <div class="section">
                <h2>Protocol Distribution</h2>
                <iframe src="protocols.html" height="500px"></iframe>
            </div>
            <div class="section">
                <h2>Protocol Details</h2>
                <iframe src="protocol_details.html" height="800px"></iframe>
            </div>
            <div class="section">
                <h2>Intrusion Summary</h2>
                <iframe src="intrusion_report.html" height="900px"></iframe>
            </div>
            <div class="section">
                <h2>Deep HTTP Analysis</h2>
                <iframe src="http_analysis.html" height="600px"></iframe>
            </div>
            <div class="section">
                <h2>Deep DNS Analysis</h2>
                <iframe src="dns_analysis.html" height="600px"></iframe>
            </div>
            <div class="section">
                <h2>Anomaly Timeline</h2>
                <iframe src="anomalies.html" height="600px"></iframe>
            </div>
        </body>
        </html>
        """
        with open(self.output_dir / output_file, "w") as f:
            f.write(html_content)

    def create_intrusion_summary(self, report: Dict[str, Any],
                                 output_file: str = "intrusion_report.html") -> None:
        """Create a styled HTML page summarizing intrusions from a JSON report.

        Expects the same structure produced by EnhancedNetworkAnalyzer.finalize().
        """
        stats = report.get('stats', {}) or {}
        alerts = report.get('alerts', {}) or {}

        # Flatten alerts and derive severity buckets
        severity_map_default = {
            'malware_indicators': 'HIGH',
            'port_scans': 'MEDIUM',
            'credential_leaks': 'CRITICAL',
            'suspicious_dns': 'MEDIUM',
            'data_exfiltration': 'CRITICAL',
            'uncommon_ports': 'LOW',
        }

        flat_alerts: List[Dict[str, Any]] = []
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts: Dict[str, int] = {}

        for alert_type, items in alerts.items():
            type_counts[alert_type] = type_counts.get(alert_type, 0) + len(items)
            for a in items:
                entry = dict(a)
                entry['type'] = alert_type
                sev = entry.get('severity') or severity_map_default.get(alert_type, 'LOW')
                entry['severity'] = sev
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                flat_alerts.append(entry)

        # Sort alerts by severity then timestamp
        sev_rank = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
        flat_alerts.sort(key=lambda x: (-sev_rank.get(x.get('severity', 'LOW'), 0), x.get('timestamp', 0)))

        # Build simple top indicators (for malware indicators)
        indicator_counts: Dict[str, int] = {}
        for a in flat_alerts:
            ind = a.get('indicator')
            if ind:
                indicator_counts[ind] = indicator_counts.get(ind, 0) + 1
        top_indicators = sorted(indicator_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

        # Simple, modern CSS layout
        css = """
        body { font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
               Ubuntu, Cantarell, 'Fira Sans', 'Droid Sans', 'Helvetica Neue', Arial, sans-serif;
               margin: 0; background: #0b1020; color: #e6eefc; }
        .container { max-width: 1200px; margin: 0 auto; padding: 32px 20px; }
        h1 { font-size: 28px; margin: 0 0 16px; }
        .muted { color: #9db0ce; }
        .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; }
        .card { background: #121a32; border: 1px solid #223055; border-radius: 12px; padding: 16px; }
        .span-4 { grid-column: span 4; }
        .span-6 { grid-column: span 6; }
        .span-12 { grid-column: span 12; }
        .metric { font-size: 22px; font-weight: 600; }
        .kpi { display: flex; align-items: baseline; gap: 10px; }
        .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; }
        .pill.CRITICAL { background: #ff3b3b20; color: #ff6c6c; border: 1px solid #ff6c6c40; }
        .pill.HIGH { background: #ff9f2f20; color: #ffba6c; border: 1px solid #ffba6c40; }
        .pill.MEDIUM { background: #ffd40020; color: #ffe16c; border: 1px solid #ffe16c40; }
        .pill.LOW { background: #00d68f20; color: #6cffc1; border: 1px solid #6cffc140; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 8px; border-bottom: 1px solid #223055; font-size: 14px; }
        th { text-align: left; color: #b9c8e4; }
        tr:hover { background: #0e1630; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; }
        .small { font-size: 12px; }
        .section-title { font-size: 18px; margin-bottom: 10px; }
        .chips { display: flex; flex-wrap: wrap; gap: 8px; }
        .chip { background: #0e1630; border: 1px solid #223055; border-radius: 999px; padding: 6px 10px; }
        """

        header_html = f"""
        <div class="grid">
          <div class="span-12">
            <h1>Intrusion Summary</h1>
            <div class="muted small">PCAP: {report.get('pcap_file','N/A')} · Generated: {report.get('generated_at','')}</div>
          </div>
        </div>
        """

        # KPI cards
        kpis_html = f"""
        <div class="grid">
          <div class="card span-4"><div class="kpi"><div class="metric">{stats.get('total_packets', 0):,}</div><div class="muted">Total Packets</div></div></div>
          <div class="card span-4"><div class="kpi"><div class="metric">{stats.get('processed_bytes', 0):,}</div><div class="muted">Processed Bytes</div></div></div>
          <div class="card span-4"><div class="kpi"><div class="metric">{sum(type_counts.values())}</div><div class="muted">Total Alerts</div></div></div>
        </div>
        """

        # Severity breakdown and counts by type
        sev_html = """
        <div class="grid">
          <div class="card span-6">
            <div class="section-title">Severity Breakdown</div>
            <div class="chips">
        """
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            sev_html += f"<span class=\"chip\"><span class=\"pill {s}\">{s}</span> {severity_counts.get(s,0)}</span>"
        sev_html += """
            </div>
          </div>
          <div class="card span-6">
            <div class="section-title">Alerts by Type</div>
            <div class="chips">
        """
        for t, c in sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True):
            sev_html += f"<span class=\"chip\">{t.replace('_',' ').title()}: {c}</span>"
        sev_html += """
            </div>
          </div>
        </div>
        """

        # Top indicators
        indicators_html = """
        <div class="grid">
          <div class="card span-12">
            <div class="section-title">Top Indicators</div>
            <div class="chips">
        """
        if top_indicators:
            for ind, cnt in top_indicators:
                indicators_html += f"<span class=\"chip\">{ind}: {cnt}</span>"
        else:
            indicators_html += "<span class=\"muted\">No indicators found</span>"
        indicators_html += """
            </div>
          </div>
        </div>
        """

        # Alerts table
        rows = []
        for a in flat_alerts[:500]:  # cap to 500 rows for performance
            ts = a.get('timestamp', '')
            src = a.get('source_ip', '')
            dst = a.get('destination_ip', '')
            typ = a.get('type', '')
            ind = a.get('indicator', '')
            sig = a.get('signature', '')
            sev = a.get('severity', 'LOW')
            rows.append(f"""
            <tr>
              <td class="small mono">{ts}</td>
              <td class="small mono">{src}</td>
              <td class="small mono">{dst}</td>
              <td>{typ.replace('_',' ').title()}</td>
              <td>{ind}</td>
              <td class="small mono">{sig}</td>
              <td><span class="pill {sev}">{sev}</span></td>
            </tr>
            """)

        table_html = f"""
        <div class="grid">
          <div class="card span-12">
            <div class="section-title">Alert Details (showing {len(rows)} of {len(flat_alerts)})</div>
            <div style="overflow:auto; max-height: 520px;">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Type</th>
                    <th>Indicator</th>
                    <th>Signature</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {''.join(rows) if rows else '<tr><td colspan="7" class="muted">No alerts</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        """

        html = f"""
        <html>
          <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <title>Intrusion Report</title>
            <style>{css}</style>
          </head>
          <body>
            <div class="container">
              {header_html}
              {kpis_html}
              {sev_html}
              {indicators_html}
              {table_html}
            </div>
          </body>
        </html>
        """

        with open(str(self.output_dir / output_file), 'w') as f:
            f.write(html)
            
    def create_http_analysis_report(self, http_requests: List[Dict[str, Any]],
                                    output_file: str = "http_analysis.html") -> None:
        """Stub method for HTTP analysis - creates basic placeholder."""
        with open(self.output_dir / output_file, "w") as f:
            f.write("<html><body><h2>HTTP Analysis - Coming Soon</h2></body></html>")
    
    def create_dns_analysis_report(self, dns_queries_and_responses: List[Dict[str, Any]],
                                   output_file: str = "dns_analysis.html") -> None:
        """Stub method for DNS analysis - creates basic placeholder."""
        with open(self.output_dir / output_file, "w") as f:
            f.write("<html><body><h2>DNS Analysis - Coming Soon</h2></body></html>")
