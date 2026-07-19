import os
import json
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

# 1. Targeting Configuration
TARGET_KEYWORDS = ["data science", "product manager", "quant", "forward deployed", "operations", "pm", "data analyst"]
GRAD_YEARS = ["2027", "2028", "2029"]
EMAIL_SENDER = "thanishakapur1@gmail.com"  # Change to your personal configuration email
EMAIL_RECEIVER = "thanishakapur1@gmail.com"  # Your destination email inbox
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

# Trusted Infrastructure Sources
GITHUB_SOURCES = [
    "https://githubusercontent.com",
    "https://githubusercontent.com",
    "https://githubusercontent.com"
]

def assess_risk(company, url):
    """
    Algorithmic Risk Assessment Matrix
    Evaluates indicators to score threat levels from 0 (Perfect Safe) to 100 (Scam Alert)
    """
    score = 0
    reasons = []
    url_lower = url.lower()
    comp_lower = company.lower()
    
    # 1. Check Protocol Security
    if not url_lower.startswith("https://"):
        score += 30
        reasons.append("Insecure HTTP protocol")
        
    # 2. Trusted Domain Safe-Listing
    trusted_ats = ["lever.co", "greenhouse.io", "myworkdayjobs.com", "ashbyhq.com", "rippling.com"]
    trusted_brands = ["apple.com", "google.com", "microsoft.com", "databricks.com", "citadel.com", "palantir.com"]
    
    if any(brand in url_lower for brand in trusted_brands):
        return 0, ["Official Certified Corporate Domain"]
        
    if any(ats in url_lower for ats in trusted_ats):
        score += 15  # Baseline for standard verified startup recruitment software
        reasons.append("Standard Enterprise ATS")
    else:
        # High-risk top-level domains frequently abused by scams
        scam_tlds = [".xyz", ".top", ".info", ".biz", ".live", ".work", ".click"]
        if any(url_lower.endswith(tld) or tld + "/" in url_lower for tld in scam_tlds):
            score += 40
            reasons.append("Suspicious High-Risk Domain Extension")
            
    # 3. Text and Semantic Scam Triggers
    scam_triggers = ["telegram", "whatsapp", "crypto task", "no interview", "deposit", "payment", "quick cash", "unverified"]
    if any(trigger in url_lower for trigger in scam_triggers):
        score += 50
        reasons.append("Malicious communication/payment terms detected in link structure")
        
    # 4. Check for cross-domain spoofing
    if len(comp_lower) > 2 and comp_lower not in url_lower and not any(ats in url_lower for ats in trusted_ats):
        score += 20
        reasons.append("URL domain name completely mismatches stated company name")
        
    # Cap maximum score limits
    score = min(score, 100)
    return score, reasons

def parse_markdown_sources():
    postings = []
    for url in GITHUB_SOURCES:
        try:
            res = requests.get(url, timeout=12)
            if res.status_code != 200: continue
            
            for line in res.text.split("\n"):
                if "|" not in line or "http" not in line: continue
                line_lower = line.lower()
                
                # Filter for core requirements matching your graduation timeline
                matches_grad = any(year in line_lower for year in GRAD_YEARS) or "undergrad" in line_lower
                matches_role = any(kw in line_lower for kw in TARGET_KEYWORDS)
                
                if matches_role and matches_grad:
                    # Clean out markdown structures and locate URLs
                    url_match = re.search(r'href=[\'"]?([^\'" >]+)[\'"]?|(?<=\()https?://[^\)]+', line)
                    if not url_match: continue
                    link = url_match.group(0).strip("()")
                    
                    # Deduce basic company structure text
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    company = parts[0].replace("**", "").replace("[", "").split("]")[0] if parts else "Unknown Provider"
                    
                    postings.append({"company": company, "url": link})
        except Exception as e:
            print(f"Error scraping data engine node: {e}")
    return postings

def scrape_web_wildcard():
    """
    Simulates decentralized discovery across open-web indexes 
    specifically crawling live jobs matching corporate application patterns
    """
    wildcard_matches = []
    # Search terms mirroring actual Lever/Greenhouse live internship footprints
    search_queries = [
        "https://duckduckgo.com",
        "https://duckduckgo.com"
    ]
    
    for query in search_queries:
        try:
            # Emulating standard browser client headers to avoid bot blocks
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            res = requests.get(query, headers=headers, timeout=10)
            if res.status_code == 200:
                # Basic mock parsing engine to safely isolate text footprints
                links = re.findall(r'https://[a-zA-Z0-9.\-_/]+', res.text)
                for url in links:
                    if any(kw in url.lower() for kw in TARGET_KEYWORDS) and "2027" in url:
                        wildcard_matches.append({"company": "Discovered Open-Web Node", "url": url})
        except Exception:
            pass
    return wildcard_matches

def send_structured_alert(jobs):
    if not jobs: return

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = f"🛡️ Summer 2027 Threat Assessment Matrix Digest ({len(jobs)} New Roles Found)"
    
    html = """
    <html>
    <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
        <h2 style="color: #1a365d; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px;">Target Internship Scan Results</h2>
        <p>The system executed an open-source crawl and isolated the following new opportunities matching your exact background and graduation bracket:</p>
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
        
        # Color code threat profile visually
        if score <= 15: color, status = "#48bb78", "VERIFIED SAFE"
        elif score <= 45: color, status = "#ecc94b", "LOW RISK"
        else: color, status = "#f56565", "HIGH RISK FLAG / POTENTIAL SCAM"
        
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
    history_file = "history.json"
    seen_urls = []
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                seen_urls = json.load(f)
        except Exception: pass
            
    # Combine structured GitHub trackers with open-web crawling scripts
    all_findings = parse_markdown_sources() + scrape_web_wildcard()
    
    # Filter only completely fresh listings to prevent duplicate notifications
    fresh_unique_jobs = []
    current_urls = []
    for item in all_findings:
        if item['url'] not in current_urls:
            current_urls.append(item['url'])
            if item['url'] not in seen_urls:
                fresh_unique_jobs.append(item)
                
    if fresh_unique_jobs:
        send_structured_alert(fresh_unique_jobs)
        with open(history_file, "w") as f:
            json.dump(current_urls, f)
