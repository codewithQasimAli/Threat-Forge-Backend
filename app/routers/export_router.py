from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.alert import Alert
import csv
import io
from datetime import datetime

router = APIRouter()

@router.get("/alerts/export/csv")
def export_alerts_csv(user_id: str, db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.user_id == user_id).order_by(Alert.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Title", "Severity", "Status", "Source IP", "Dest IP", "RMSE Score", "Acknowledged", "Created At"])
    for a in alerts:
        writer.writerow([
            str(a.id),
            a.title or "",
            a.severity or "",
            a.status or "",
            a.source_ip or "",
            a.dest_ip or "",
            str(a.rmse_score or ""),
            str(a.acknowledged or False),
            str(a.created_at or ""),
        ])
    output.seek(0)
    filename = f"threatforge_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/alerts/export/pdf")
def export_alerts_pdf(user_id: str, db: Session = Depends(get_db)):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    alerts = db.query(Alert).filter(Alert.user_id == user_id).order_by(Alert.created_at.desc()).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("ThreatForge — Alert Report", styles['Title']))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"Total Alerts: {len(alerts)}", styles['Normal']))
    elements.append(Spacer(1, 20))

    data = [["Title", "Severity", "Source IP", "Status", "Created At"]]
    for a in alerts:
        data.append([
            str(a.title or "")[:40],
            str(a.severity or ""),
            str(a.source_ip or ""),
            str(a.status or ""),
            str(a.created_at)[:19] if a.created_at else "",
        ])

    table = Table(data, colWidths=[180, 70, 100, 70, 120])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1d8ca9')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f5f5f5')]),
        ('FONTSIZE', (0,1), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    filename = f"threatforge_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
