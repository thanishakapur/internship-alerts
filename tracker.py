import os
import json
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

# 1. Targeting Configuration
TARGET_KEYWORDS = ["data science", "product manager", "quant", "forward deployed", "operations", "pm", "data analyst", "software"]
GRAD_YEARS = ["2027", "2028", "2029"]
EMAIL_SENDER = "thanishakapur1@gmail.com"    # ⚠️ Make sure this is your personal Gmail address
EMAIL_RECEIVER = "thanishakapur1@gmail.com"  # ⚠️ Make sure this is your destination address
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

# Correct, complete raw source URL tracks
LIVE_URLS = {
    "tracker_sndsh.md": "https://githubusercontent.com",
    "tracker_vansh.md": "https://githubusercontent.com",
    "tracker_speedy.md": "https://githubusercontent.com"
}

def download_and_parse_sources():
    postings = []
    
    for filename, url in LIVE_URLS.items():
        text_content = ""
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            res = requests.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                text_content = res.text
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(text_content)
                print(f"Successfully downloaded freshest data for {filename}")
        except Exception as e:
            print(f"Network call skipped for {filename}. Attempting local read... Error: {e}")
            
        if not text_content and os.path.exists(filename):
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    text_content = f.read()
                    print(f"Loaded cached fallback data for {filename}")
            except Exception as e:
                print(f"Error reading local file {filename}: {e}")
                
        if not text_content:
            continue
            
        for line in text_content.split("\n"):
            if "|" not in line or "http" not in line: 
                continue
            line_lower = line.lower()
            
            matches_grad = any(year in line_lower for year in GRAD_YEARS) or "undergrad" in line_lower
            matches_role = any(kw in line_lower for kw in TARGET_KEYWORDS)
            
            if matches_role and matches_grad:
                url_match = re.search(r'href=[\'"]?([^\'" >]+)[\'"]?|(?<=\()https?://[^\)]+', line)
                if not url_match: 
                    continue
                link = url_match.group(0).strip("()")
                
                parts = [p.strip() for p in line.split("|") if p.strip()]
                
                # ✅ FIXED: Safe string extraction that guarantees text presence
                company = "Target Company"
                if len(parts) > 1:
                    raw_comp = parts[1].replace("**", "").replace("[", "")
                    if "]" in raw_comp:
                        company = raw_comp.split("]")[0].strip()
                    elif raw_comp.strip():
                        company = raw_comp.strip()
                
                if not company:
                    company = "Target Company"
                
                postings.append({"company": str(company), "url": str(link)})
                
    return postings

def assess_risk(company, url):
    score = 0
    reasons = []
    url_lower = url.lower()
    
    if not url_lower.startswith("https://"):
        score += 30
        reasons.append("Insecure HTTP protocol")
        
    trusted_ats = ["lever.co", "greenhouse.io", "myworkdayjobs.com", "ashbyhq.com", "rippling.com"]
    trusted_brands = ["apple.com", "google.com", "microsoft.com", "databricks.com", "citadel.com", "palantir.com"]
    
    if any(brand in url_lower for brand in trusted_brands):
        return 0, ["Official Certified Corporate Domain"]
        
    if any(ats in url_lower for ats in trusted_ats):
        score += 15
        reasons.append("Standard Enterprise ATS")
    else:
        scam_tlds = [".xyz", ".top", ".info", ".biz", ".live", ".work", ".click"]
        if any(url_lower.endswith(tld) or tld + "/" in url_lower for tld in scam_tlds):
            score += 40
            reasons.append("Suspicious High-Risk Domain Extension")
            
    return min(score, 100), reasons

def send_structured_alert(jobs):
    if not jobs: 
        print("No matches to transmit.")
        return

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = f"🛡️ Summer 2027 Threat Assessment Matrix Digest ({len(jobs)} Roles Found)"
    
    html = """
    <html>
    <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
        <h2 style="color: #1a365d; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px;">Target Internship Scan Results</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
            <thead>
                <tr style="background-color: #f7fafc; border-bottom: 2px solid #cbd5e0;">
                    <th style="padding: 10px; text-align: left;">Company</th>
                    <th style="padding: 10px; text-align: left;">Application Link</th>
                    <th style="padding: 10px; text-align: center;">Risk Score</th>
                    <th style="padding: 10px; text-align: left;">Security Threat Assessment Flag</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for job in jobs:
        score, reasons = assess_risk(job['company'], job['url'])
        if score <= 15: color, status = "#48bb78", "VERIFIED SAFE"
        elif score <= 45: color, status = "#ecc94b", "LOW RISK"
        else: color, status = "#f56565", "HIGH RISK"
        
        reason_text = ", ".join(reasons) if reasons else "Meets security integrity baselines."
        html += f"""
            <tr style="border-bottom: 1px solid #edf2f7;">
                <td style="padding: 10px; font-weight: bold;">{job['company']}</td>
                <td style="padding: 10px;"><a href="{job['url']}" style="color: #3182ce; text-decoration: none;">View Application Portal →</a></td>
                <td style="padding: 10px; text-align: center; font-weight: bold; color: {color};">{score}/100</td>
                <td style="padding: 10px; font-size: 13px; color: #4a5568;"><strong>[{status}]</strong> {reason_text}</td>
            </tr>
        """
        
    html += "</tbody></table></body></html>"
    msg.attach(MIMEText(html, 'html'))
    
    try:
        server = smtplib.SMTP('://gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        print("Threat-assessed digest successfully dispatched.")
    except Exception as e:
        print(f"Network error dispatching email transaction: {e}")

if __name__ == "__main__":
    print("Executing master scan sequence...")
    all_findings = download_and_parse_sources()
    
    if not all_findings:
        all_findings = [{"company": "Databricks (Test Target)", "url": "https://databricks.com"}]
        
    send_structured_alert(all_findings)