"""
Export Module for DeepPhish
Handles PDF and CSV export of analysis results
"""
import csv
import io
from datetime import datetime
from typing import Dict, Any, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def export_to_pdf(analysis: Dict[str, Any], user_email: Optional[str] = None) -> bytes:
    """
    Export analysis result to PDF format
    Returns PDF bytes
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#333333'),
        spaceAfter=12,
        spaceBefore=20
    )
    
    # Title
    story.append(Paragraph("DeepPhish Analysis Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Metadata
    created_at = analysis.get("created_at", "")
    if created_at:
        try:
            # Try to format date string
            if isinstance(created_at, str):
                if len(created_at) >= 19:
                    created_at = created_at[:19]
                else:
                    created_at = str(created_at)
            else:
                created_at = str(created_at)
        except:
            created_at = "N/A"
    else:
        created_at = "N/A"
    
    metadata = [
        ["Analysis Date", created_at],
        ["Analysis Type", str(analysis.get("analysis_type", "N/A")).upper()],
        ["Risk Level", str(analysis.get("risk_level", "N/A"))],
        ["Phishing Detected", "Yes" if analysis.get("is_phishing") else "No"],
    ]
    
    if user_email:
        metadata.insert(1, ["User", str(user_email)])
    
    confidence = analysis.get("confidence")
    if confidence is not None:
        try:
            confidence_pct = f"{float(confidence):.2%}"
            metadata.append(["Confidence", confidence_pct])
        except (ValueError, TypeError):
            pass
    
    metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey)
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Analysis Results
    result_data = analysis.get("result_data", {})
    
    # NLU Analysis
    if result_data.get("nlu_analysis"):
        story.append(Paragraph("NLU Text Analysis", heading_style))
        nlu = result_data["nlu_analysis"]
        
        nlu_info = [
            ["Prediction", nlu.get("prediction", "N/A")],
            ["Is Phishing", "Yes" if nlu.get("is_phishing") else "No"],
            ["Confidence", f"{nlu.get('confidence', 0):.2%}"],
        ]
        
        if nlu.get("explainability") and nlu["explainability"].get("top_concerns"):
            concerns = nlu["explainability"]["top_concerns"]
            if concerns:
                story.append(Paragraph("Key Concerns:", styles['Normal']))
                for concern in concerns[:5]:  # Top 5
                    story.append(Paragraph(
                        f"• {concern.get('word', 'N/A')}: {concern.get('explanation', 'N/A')}",
                        styles['Normal']
                    ))
        
        nlu_table = Table(nlu_info, colWidths=[2*inch, 4*inch])
        nlu_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f9ff')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(nlu_table)
        story.append(Spacer(1, 0.2*inch))
    
    # DNN Analysis
    if result_data.get("dnn_analysis"):
        story.append(Paragraph("DNN URL Analysis", heading_style))
        dnn = result_data["dnn_analysis"]
        
        if isinstance(dnn, list):
            dnn = dnn[0] if dnn else {}
        
        if not dnn.get("error"):
            dnn_info = [
                ["Is Phishing", "Yes" if dnn.get("is_phishing") else "No"],
                ["Confidence", f"{dnn.get('confidence', 0):.2%}"],
                ["URL", dnn.get("url", "N/A")],
            ]
            
            dnn_table = Table(dnn_info, colWidths=[2*inch, 4*inch])
            dnn_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#fff5f5')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(dnn_table)
            story.append(Spacer(1, 0.2*inch))
    
    # VirusTotal Analysis
    if result_data.get("vt_analysis"):
        story.append(Paragraph("VirusTotal Analysis", heading_style))
        vt = result_data["vt_analysis"]
        
        if isinstance(vt, dict) and vt.get("last_analysis_stats"):
            stats = vt["last_analysis_stats"]
            vt_info = [
                ["Malicious", str(stats.get("malicious", 0))],
                ["Suspicious", str(stats.get("suspicious", 0))],
                ["Harmless", str(stats.get("harmless", 0))],
                ["Undetected", str(stats.get("undetected", 0))],
            ]
            
            if vt.get("ip"):
                vt_info.insert(0, ["IP Address", vt["ip"]])
            if vt.get("url"):
                vt_info.insert(0, ["URL", vt["url"]])
            
            vt_table = Table(vt_info, colWidths=[2*inch, 4*inch])
            vt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9f9f9')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(vt_table)
            story.append(Spacer(1, 0.2*inch))
    
    # Risk Assessment
    if result_data.get("risk_assessment"):
        story.append(Paragraph("Risk Assessment", heading_style))
        risk = result_data["risk_assessment"]
        
        risk_info = [
            ["Risk Level", risk.get("risk_level", "N/A")],
            ["Risk Score", f"{risk.get('risk_score', 0):.2f}"],
            ["Recommendation", risk.get("recommendation", "N/A")],
        ]
        
        if risk.get("risk_factors"):
            factors = "\n".join([f"• {factor}" for factor in risk["risk_factors"]])
            risk_info.append(["Risk Factors", factors])
        
        risk_table = Table(risk_info, colWidths=[2*inch, 4*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#fff9e6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('VALIGN', (1, 3), (1, 3), 'TOP')
        ]))
        story.append(risk_table)
    
    # Footer
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph(
        f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=TA_CENTER, textColor=colors.grey)
    ))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def export_to_csv(analysis: Dict[str, Any]) -> str:
    """
    Export analysis result to CSV format
    Returns CSV string
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["DeepPhish Analysis Report"])
    writer.writerow([])
    
    # Metadata
    writer.writerow(["Field", "Value"])
    writer.writerow(["Analysis ID", str(analysis.get("id", "N/A"))])
    
    created_at = analysis.get("created_at", "")
    if created_at:
        try:
            if isinstance(created_at, str) and len(created_at) >= 19:
                created_at = created_at[:19]
            else:
                created_at = str(created_at)
        except:
            created_at = "N/A"
    else:
        created_at = "N/A"
    writer.writerow(["Analysis Date", created_at])
    
    writer.writerow(["Analysis Type", str(analysis.get("analysis_type", "N/A"))])
    writer.writerow(["Risk Level", str(analysis.get("risk_level", "N/A"))])
    writer.writerow(["Is Phishing", "Yes" if analysis.get("is_phishing") else "No"])
    
    confidence = analysis.get("confidence")
    if confidence is not None:
        try:
            confidence_str = f"{float(confidence):.2%}"
        except (ValueError, TypeError):
            confidence_str = str(confidence)
    else:
        confidence_str = "N/A"
    writer.writerow(["Confidence", confidence_str])
    
    risk_score = analysis.get("risk_score")
    writer.writerow(["Risk Score", str(risk_score) if risk_score is not None else "N/A"])
    writer.writerow([])
    
    # Analysis Results
    result_data = analysis.get("result_data", {})
    
    # NLU Analysis
    if result_data.get("nlu_analysis"):
        writer.writerow(["NLU Analysis"])
        nlu = result_data["nlu_analysis"]
        writer.writerow(["Prediction", nlu.get("prediction", "N/A")])
        writer.writerow(["Is Phishing", "Yes" if nlu.get("is_phishing") else "No"])
        writer.writerow(["Confidence", f"{nlu.get('confidence', 0):.2%}"])
        
        if nlu.get("explainability") and nlu["explainability"].get("top_concerns"):
            writer.writerow([])
            writer.writerow(["Key Concerns"])
            writer.writerow(["Word", "Explanation", "Importance"])
            for concern in nlu["explainability"]["top_concerns"]:
                writer.writerow([
                    concern.get("word", "N/A"),
                    concern.get("explanation", "N/A"),
                    concern.get("importance", "N/A")
                ])
        writer.writerow([])
    
    # DNN Analysis
    if result_data.get("dnn_analysis"):
        writer.writerow(["DNN Analysis"])
        dnn = result_data["dnn_analysis"]
        if isinstance(dnn, list):
            dnn = dnn[0] if dnn else {}
        if not dnn.get("error"):
            writer.writerow(["URL", dnn.get("url", "N/A")])
            writer.writerow(["Is Phishing", "Yes" if dnn.get("is_phishing") else "No"])
            writer.writerow(["Confidence", f"{dnn.get('confidence', 0):.2%}"])
        writer.writerow([])
    
    # VirusTotal Analysis
    if result_data.get("vt_analysis"):
        writer.writerow(["VirusTotal Analysis"])
        vt = result_data["vt_analysis"]
        if isinstance(vt, dict):
            if vt.get("ip"):
                writer.writerow(["IP Address", vt["ip"]])
            if vt.get("url"):
                writer.writerow(["URL", vt["url"]])
            if vt.get("last_analysis_stats"):
                stats = vt["last_analysis_stats"]
                writer.writerow(["Malicious", stats.get("malicious", 0)])
                writer.writerow(["Suspicious", stats.get("suspicious", 0)])
                writer.writerow(["Harmless", stats.get("harmless", 0)])
                writer.writerow(["Undetected", stats.get("undetected", 0)])
        writer.writerow([])
    
    # Risk Assessment
    if result_data.get("risk_assessment"):
        writer.writerow(["Risk Assessment"])
        risk = result_data["risk_assessment"]
        writer.writerow(["Risk Level", risk.get("risk_level", "N/A")])
        writer.writerow(["Risk Score", risk.get("risk_score", "N/A")])
        writer.writerow(["Recommendation", risk.get("recommendation", "N/A")])
        if risk.get("risk_factors"):
            writer.writerow([])
            writer.writerow(["Risk Factors"])
            for factor in risk["risk_factors"]:
                writer.writerow([factor])
    
    return output.getvalue()

