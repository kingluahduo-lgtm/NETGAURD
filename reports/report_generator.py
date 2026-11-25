import os
import json
import csv
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from utils.logger import get_app_logger

logger = get_app_logger()

class ReportGenerator:
    def __init__(self, db_manager):
        self.db = db_manager

    def export_csv(self, session_id: str, file_path: str) -> bool:
        """Export all packets in session to a CSV file."""
        try:
            packets = self.db.get_packets(session_id, limit=10000)
            if not packets:
                logger.warning(f"No packets found in session {session_id} to export to CSV.")
                return False
                
            keys = packets[0].keys()
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(packets)
            logger.info(f"Session {session_id} exported to CSV at {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting CSV: {e}")
            return False

    def export_json(self, session_id: str, file_path: str) -> bool:
        """Export all packets and alerts in session to a JSON file."""
        try:
            packets = self.db.get_packets(session_id, limit=5000)
            alerts = self.db.get_alerts(session_id, limit=1000)
            session_info = self.db.get_session(session_id)
            
            data = {
                "session": session_info,
                "alerts": alerts,
                "packets": packets
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Session {session_id} exported to JSON at {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")
            return False

    def generate_pdf_report(self, session_id: str, file_path: str) -> bool:
        """
        Generates a professional, industry-grade cybersecurity report using ReportLab.
        Contains: Executive Summary, Alert Levels table, Protocol Stats, Top IPs, recommendations.
        """
        try:
            session_info = self.db.get_session(session_id)
            if not session_info:
                logger.warning(f"Session {session_id} not found. Cannot generate PDF.")
                return False
                
            agg_stats = self.db.get_aggregate_stats(session_id)
            protocol_stats = self.db.get_protocol_stats(session_id)
            top_src_ips = self.db.get_top_ips(session_id, "src_ip", 5)
            top_dst_ips = self.db.get_top_ips(session_id, "dst_ip", 5)
            alerts = self.db.get_alerts(session_id, limit=100)
            
            # Setup Document
            doc = SimpleDocTemplate(
                file_path,
                pagesize=letter,
                rightMargin=54, leftMargin=54,
                topMargin=54, bottomMargin=54
            )
            
            styles = getSampleStyleSheet()
            
            # Custom Color Palette (Cybersecurity Dark / Professional themed PDF)
            primary_color = colors.HexColor("#0f172a") # Slate 900
            secondary_color = colors.HexColor("#1e293b") # Slate 800
            accent_blue = colors.HexColor("#2563eb") # Blue 600
            light_grey = colors.HexColor("#f8fafc") # Slate 50
            border_grey = colors.HexColor("#cbd5e1") # Slate 300
            
            # Text Styles
            title_style = ParagraphStyle(
                'CoverTitle',
                parent=styles['Normal'],
                fontName='Helvetica-Bold',
                fontSize=26,
                leading=32,
                textColor=primary_color,
                spaceAfter=10
            )
            
            subtitle_style = ParagraphStyle(
                'CoverSubtitle',
                parent=styles['Normal'],
                fontName='Helvetica',
                fontSize=14,
                leading=18,
                textColor=colors.HexColor("#475569"),
                spaceAfter=30
            )
            
            h1_style = ParagraphStyle(
                'SectionHeader',
                parent=styles['Heading1'],
                fontName='Helvetica-Bold',
                fontSize=18,
                leading=22,
                textColor=primary_color,
                spaceBefore=15,
                spaceAfter=10,
                keepWithNext=True
            )

            h2_style = ParagraphStyle(
                'SubSectionHeader',
                parent=styles['Heading2'],
                fontName='Helvetica-Bold',
                fontSize=13,
                leading=16,
                textColor=accent_blue,
                spaceBefore=12,
                spaceAfter=6,
                keepWithNext=True
            )

            body_style = ParagraphStyle(
                'BodyTextCustom',
                parent=styles['BodyText'],
                fontName='Helvetica',
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#334155"),
                spaceAfter=8
            )

            meta_label_style = ParagraphStyle(
                'MetaLabel',
                parent=styles['Normal'],
                fontName='Helvetica-Bold',
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#475569")
            )

            meta_val_style = ParagraphStyle(
                'MetaValue',
                parent=styles['Normal'],
                fontName='Helvetica',
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#0f172a")
            )

            story = []
            
            # --- COVER PAGE / HEADER ---
            story.append(Spacer(1, 20))
            story.append(Paragraph("NETGUARD SECURITY AUDIT REPORT", title_style))
            story.append(Paragraph("Network Threat Analysis & Forensic Traffic Report", subtitle_style))
            story.append(Spacer(1, 10))
            
            # Session Metadata block
            created_dt = datetime.fromtimestamp(session_info["created_at"]).strftime('%Y-%m-%d %H:%M:%S')
            meta_data = [
                [Paragraph("Session Identifier:", meta_label_style), Paragraph(session_id, meta_val_style)],
                [Paragraph("Session Name:", meta_label_style), Paragraph(session_info["name"], meta_val_style)],
                [Paragraph("Analysis Date / Time:", meta_label_style), Paragraph(created_dt, meta_val_style)],
                [Paragraph("Total Packets Analyzed:", meta_label_style), Paragraph(f"{agg_stats.get('total_packets', 0):,}", meta_val_style)],
                [Paragraph("Threat Alerts Flagged:", meta_label_style), Paragraph(f"{agg_stats.get('total_alerts', 0):,}", meta_val_style)]
            ]
            
            meta_table = Table(meta_data, colWidths=[2.0*inch, 4.5*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), light_grey),
                ('PADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 30))
            
            # --- EXECUTIVE SUMMARY ---
            story.append(Paragraph("1. Executive Summary", h1_style))
            summary_p1 = (
                "NetGuard Threat Analyzer monitored live network traffic during this capture session. "
                "The target environment was analyzed using protocol signature validation and dynamic "
                "intrusion detection rules. The primary objective was to map device activity, catalog "
                "protocol layouts, and flag anomalies such as scanning, flooding, and hardware spoofing."
            )
            story.append(Paragraph(summary_p1, body_style))
            
            total_alerts = agg_stats.get('total_alerts', 0)
            if total_alerts > 0:
                summary_p2 = (
                    f"<b>Security Posture Warning:</b> A total of {total_alerts} security anomalies were "
                    "triggered during this capture session. Security administrators should review the "
                    "individual logs below to assess potential intrusions, port scans, or denial-of-service attempts."
                )
            else:
                summary_p2 = (
                    "<b>Security Posture Healthy:</b> No high-severity security incidents or threat anomalies "
                    "were detected during the tracking period. Regular network audits are recommended to "
                    "maintain baseline profiles."
                )
            story.append(Paragraph(summary_p2, body_style))
            story.append(Spacer(1, 20))
            
            # --- INCIDENT & THREAT SUMMARY ---
            story.append(Paragraph("2. Threat Analysis Logs", h1_style))
            if not alerts:
                story.append(Paragraph("No security alerts were generated during this session.", body_style))
            else:
                alert_table_data = [[
                    Paragraph("<b>Timestamp</b>", meta_label_style),
                    Paragraph("<b>Threat Vector</b>", meta_label_style),
                    Paragraph("<b>Severity</b>", meta_label_style),
                    Paragraph("<b>Source IP</b>", meta_label_style),
                    Paragraph("<b>Details</b>", meta_label_style)
                ]]
                
                for a in alerts[:15]:  # Cap table list at 15 for readable PDF size
                    a_time = datetime.fromtimestamp(a["timestamp"]).strftime('%H:%M:%S')
                    
                    # Highlight cell based on severity
                    sev = a["severity"].capitalize()
                    if sev == "Critical":
                        sev_style = ParagraphStyle('Crit', parent=meta_label_style, textColor=colors.red)
                    elif sev == "High":
                        sev_style = ParagraphStyle('High', parent=meta_label_style, textColor=colors.orange)
                    elif sev == "Medium":
                        sev_style = ParagraphStyle('Med', parent=meta_label_style, textColor=colors.HexColor("#d97706")) # Dark Amber
                    else:
                        sev_style = ParagraphStyle('Low', parent=meta_label_style, textColor=colors.HexColor("#0284c7")) # Sky
                        
                    alert_table_data.append([
                        Paragraph(a_time, meta_val_style),
                        Paragraph(a["threat_type"], meta_val_style),
                        Paragraph(sev, sev_style),
                        Paragraph(a["src_ip"] or "N/A", meta_val_style),
                        Paragraph(a["details"], meta_val_style)
                    ])
                    
                alert_table = Table(alert_table_data, colWidths=[0.8*inch, 1.6*inch, 0.8*inch, 1.1*inch, 2.7*inch])
                alert_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), secondary_color),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('LINEBELOW', (0,0), (-1,-1), 0.5, border_grey),
                    ('VALIGN', (0,0), (-1,-1), 'TOP')
                ]))
                # Apply white text to table headers
                for i in range(5):
                    alert_table_data[0][i].style.textColor = colors.white
                story.append(alert_table)
                
                if len(alerts) > 15:
                    story.append(Spacer(1, 5))
                    story.append(Paragraph(f"<i>* Showing top 15 alerts of {len(alerts)} total alerts. Review JSON report for complete logs.</i>", body_style))
            
            story.append(PageBreak())
            
            # --- PROTOCOL & TRAFFIC ANALYSIS ---
            story.append(Paragraph("3. Protocol Statistics", h1_style))
            if not protocol_stats:
                story.append(Paragraph("No protocol statistics recorded.", body_style))
            else:
                proto_data = [[
                    Paragraph("<b>Protocol</b>", meta_label_style),
                    Paragraph("<b>Packet Count</b>", meta_label_style),
                    Paragraph("<b>Total Volume (Bytes)</b>", meta_label_style),
                    Paragraph("<b>Percentage (%)</b>", meta_label_style)
                ]]
                
                total_p = agg_stats.get("total_packets") or 1
                for pr in protocol_stats:
                    pct = round((pr["count"] / total_p) * 100, 1)
                    proto_data.append([
                        Paragraph(pr["protocol"], meta_val_style),
                        Paragraph(f"{pr['count']:,}", meta_val_style),
                        Paragraph(f"{pr['bytes'] or 0:,}", meta_val_style),
                        Paragraph(f"{pct}%", meta_val_style)
                    ])
                    
                proto_table = Table(proto_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
                proto_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), secondary_color),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('LINEBELOW', (0,0), (-1,-1), 0.5, border_grey),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
                ]))
                for i in range(4):
                    proto_data[0][i].style.textColor = colors.white
                story.append(proto_table)
            
            story.append(Spacer(1, 15))
            
            # --- TOP IP TALKERS ---
            story.append(Paragraph("4. Traffic Source / Destination Analysis", h1_style))
            
            col_widths = [2.0*inch, 1.5*inch, 1.5*inch]
            
            # Top Sources table
            story.append(Paragraph("Top 5 Source IP Addresses", h2_style))
            if not top_src_ips:
                story.append(Paragraph("No source IP details recorded.", body_style))
            else:
                src_data = [[
                    Paragraph("<b>Source IP</b>", meta_label_style),
                    Paragraph("<b>Packet Count</b>", meta_label_style),
                    Paragraph("<b>Total Bytes</b>", meta_label_style)
                ]]
                for s in top_src_ips:
                    src_data.append([
                        Paragraph(s["ip"], meta_val_style),
                        Paragraph(f"{s['count']:,}", meta_val_style),
                        Paragraph(f"{s['bytes'] or 0:,}", meta_val_style)
                    ])
                src_table = Table(src_data, colWidths=col_widths)
                src_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), secondary_color),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('LINEBELOW', (0,0), (-1,-1), 0.5, border_grey)
                ]))
                for i in range(3):
                    src_data[0][i].style.textColor = colors.white
                story.append(src_table)
                
            story.append(Spacer(1, 10))

            # Top Destinations table
            story.append(Paragraph("Top 5 Destination IP Addresses", h2_style))
            if not top_dst_ips:
                story.append(Paragraph("No destination IP details recorded.", body_style))
            else:
                dst_data = [[
                    Paragraph("<b>Destination IP</b>", meta_label_style),
                    Paragraph("<b>Packet Count</b>", meta_label_style),
                    Paragraph("<b>Total Bytes</b>", meta_label_style)
                ]]
                for d in top_dst_ips:
                    dst_data.append([
                        Paragraph(d["ip"], meta_val_style),
                        Paragraph(f"{d['count']:,}", meta_val_style),
                        Paragraph(f"{d['bytes'] or 0:,}", meta_val_style)
                    ])
                dst_table = Table(dst_data, colWidths=col_widths)
                dst_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), secondary_color),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('LINEBELOW', (0,0), (-1,-1), 0.5, border_grey)
                ]))
                for i in range(3):
                    dst_data[0][i].style.textColor = colors.white
                story.append(dst_table)
            
            story.append(Spacer(1, 20))
            
            # --- SECURITY RECOMMENDATIONS ---
            story.append(Paragraph("5. Hardened Security Recommendations", h1_style))
            
            recs = []
            
            # Analyze alerts to generate context-specific suggestions
            threats_found = set(a["threat_type"] for a in alerts)
            
            if "ARP Spoofing Detected" in threats_found:
                recs.append(
                    "<b>Mitigate ARP Poisoning:</b> Implement static ARP bindings for critical infrastructure servers. "
                    "Configure Dynamic ARP Inspection (DAI) on switch interfaces and deploy 802.1X network access control."
                )
            if any(t for t in threats_found if "Flood" in t):
                recs.append(
                    "<b>Defend Against Flooding / DoS:</b> Configure rate limiting on internet-facing firewalls. "
                    "Deploy SYN Cookies on Linux gateways to resist SYN floods, and block unneeded ICMP packets on boundary routers."
                )
            if "Port Scanning Activity" in threats_found:
                recs.append(
                    "<b>Prevent Reconnaissance / Port Scans:</b> Disable unused network services. Deploy an active firewall "
                    "or Intrusion Prevention System (IPS) like Snort/Suricata to dynamically blackhole IPs probing ports."
                )
            if "Excessive Failed SSH Connections" in threats_found:
                recs.append(
                    "<b>Secure SSH Interfaces:</b> Deploy Fail2ban to block IPs showing successive authentication failures. "
                    "Disable password authentication in sshd_config, force key-based access, and move listening ports off default 22."
                )
                
            # Default general recommendations
            recs.append(
                "<b>Implement Network Segmentation:</b> Isolate guest wireless networks, corporate endpoints, and secure databases "
                "using distinct Virtual LANs (VLANs) and access control filters."
            )
            recs.append(
                "<b>Audit and Continuous Monitor:</b> Establish a centralized syslog / SIEM solution to ingest NetGuard alerts "
                "and monitor network baselines for out-of-character bandwidth or packet-rate spikes."
            )
            
            for idx, r in enumerate(recs, 1):
                story.append(Paragraph(f"{idx}. {r}", body_style))
                story.append(Spacer(1, 4))
                
            # Render Document
            doc.build(story)
            logger.info(f"Session {session_id} PDF audit report generated at {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}", exc_info=True)
            return False
