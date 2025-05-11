"""
Report generation module for NMAP-Guard.
"""

import json
from typing import Dict, Optional
from datetime import datetime
from ..core.config import settings
from ..utils.logging import get_logger

logger = get_logger(__name__)

class ReportGenerator:
    """Report generator for scan results."""
    
    def __init__(self):
        self.max_reports = settings.MAX_REPORTS
        self.retention_days = settings.REPORT_RETENTION_DAYS
    
    def generate_report(
        self,
        scan_data: Dict,
        report_type: str = "summary",
        format: str = "json",
        include_details: bool = True
    ) -> Dict:
        """
        Generate a report from scan data.
        
        Args:
            scan_data: Dictionary containing scan results
            report_type: Type of report to generate (summary/detailed)
            format: Output format (json/html/pdf)
            include_details: Whether to include detailed information
            
        Returns:
            Dictionary containing the generated report
        """
        try:
            # Generate report content
            if report_type == "summary":
                content = self._generate_summary_report(scan_data)
            elif report_type == "detailed":
                content = self._generate_detailed_report(scan_data, include_details)
            else:
                raise ValueError(f"Invalid report type: {report_type}")
            
            # Format report
            if format == "json":
                return self._format_json(content)
            elif format == "html":
                return self._format_html(content)
            elif format == "pdf":
                return self._format_pdf(content)
            else:
                raise ValueError(f"Invalid format: {format}")
                
        except Exception as e:
            logger.error(f"Failed to generate report: {str(e)}")
            raise
    
    def _generate_summary_report(self, scan_data: Dict) -> Dict:
        """Generate a summary report."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "scan_id": scan_data.get("scan_id"),
            "status": scan_data.get("status"),
            "summary": scan_data.get("summary", {}),
            "duration": scan_data.get("duration")
        }
    
    def _generate_detailed_report(self, scan_data: Dict, include_details: bool) -> Dict:
        """Generate a detailed report."""
        report = self._generate_summary_report(scan_data)
        if include_details:
            report["details"] = scan_data.get("raw_output")
        return report
    
    def _format_json(self, content: Dict) -> Dict:
        """Format report as JSON."""
        return {
            "format": "json",
            "content": json.dumps(content, indent=2)
        }
    
    def _format_html(self, content: Dict) -> Dict:
        """Format report as HTML."""
        # Basic HTML template
        html = f"""
        <html>
        <head>
            <title>NMAP Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
                .details {{ margin-top: 20px; }}
            </style>
        </head>
        <body>
            <h1>NMAP Scan Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Scan ID: {content.get('scan_id')}</p>
                <p>Status: {content.get('status')}</p>
                <p>Duration: {content.get('duration')} seconds</p>
            </div>
        </body>
        </html>
        """
        return {
            "format": "html",
            "content": html
        }
    
    def _format_pdf(self, content: Dict) -> Dict:
        """Format report as PDF."""
        # In a real implementation, you would use a PDF generation library
        return {
            "format": "pdf",
            "content": "PDF generation not implemented"
        } 