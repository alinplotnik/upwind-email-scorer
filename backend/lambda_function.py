import json
import re
import os
import urllib.request
import urllib.error
import time
from datetime import datetime

ai_init_error = None
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", GEMINI_API_KEY)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

if not GEMINI_API_KEY:
    ai_init_error = "API Key Not Found: The 'GEMINI_API_KEY' environment variable is missing in AWS Lambda."

def scrub_pii(text):
    if not text:
        return ""
    # Redact potential credit cards and bank account numbers (12-19 digits, possibly with spaces/dashes)
    text = re.sub(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b', '[REDACTED CARD/ACCOUNT]', text)
    # Redact standard phone numbers
    text = re.sub(r'\b(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b', '[REDACTED PHONE]', text)
    # Redact potential SSN or ID numbers
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED ID]', text)
    # Redact long sequence of numbers (e.g. tracking numbers, billing accounts, zip codes)
    text = re.sub(r'\b\d{5,}\b', '[REDACTED NUMBER]', text)
    # Redact email addresses
    text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[REDACTED EMAIL]', text)
    return text

def lambda_handler(event, context):
    # Default values in case the email is safe or data is missing
    score = 0
    verdict = "Safe"
    reasons_found = []
    ai_analysis = None
    
    try:
        # 1. Extract the payload sent by the Gmail Add-on
        if 'body' in event:
            body = json.loads(event['body'])
            use_ai = body.get('use_ai', False)
            raw_sender = body.get('sender', '')
            sender = raw_sender.lower()
            subject = body.get('subject', '').lower()
            content = body.get('content', '').lower()
            content_html = body.get('content_html', '')
            user_email = body.get('user_email', '').lower()
            attachment_hashes = body.get('attachment_hashes', [])
            email_date = body.get('email_date', 'Unknown Date')
            auth_results = body.get('auth_results', '').lower()
            
            # --- SENDER ANALYSIS ---
            # Extract email address if format is "Name <email@domain.com>"
            email_address = sender
            email_match = re.search(r'<([^>]+)>', sender)
            sender_name = sender
            if email_match:
                email_address = email_match.group(1).lower()
                sender_name = sender.replace(f"<{email_match.group(1)}>", "").strip().strip('"').strip("'")
                
            # 0. Sent yourself check
            if user_email and email_address and email_address.strip().lower() == user_email.strip().lower():
                response_data = {
                    "score": 0,
                    "verdict": "Safe",
                    "reasoning": "You sent this email."
                }
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps(response_data)
                }
            
            # 0.5 Upwind Easter Egg (Interview Magic)
            if "upwind" in email_address.lower() or "upwind" in sender_name.lower() or "comeet" in email_address.lower():
                response_data = {
                    "score": 0,
                    "verdict": "🏄‍♂️ UPWIND VIP 🏄‍♀️",
                    "reasoning": "🎉 Welcome Team Upwind!<br><br>This email bypassed all security checks because Upwind is inherently trusted (and because the developer really wants to work here! 😉).",
                    "ai_analysis": "No AI analysis needed for the ultimate cloud security company. 🏄‍♂️🏄‍♀️"
                }
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps(response_data)
                }
            
            # Check for free providers
            is_free_provider = False
            free_providers = ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com", "@aol.com", "@protonmail.com"]
            if any(provider in email_address for provider in free_providers):
                is_free_provider = True
                # No automatic score penalty for free providers to avoid flagging personal emails from family/friends
            
            # Check for suspicious sender names (impersonation check)
            is_impersonation = False
            
            # 1. Exact Brand Domain Matching
            brand_domains = {
                "paypal": ["paypal.com"],
                "apple": ["apple.com"],
                "microsoft": ["microsoft.com"],
                "google": ["google.com"],
                "amazon": ["amazon.com"],
                "netflix": ["netflix.com"]
            }
            
            email_domain = email_address.split('@')[-1] if '@' in email_address else ""
            
            for brand, allowed_domains in brand_domains.items():
                if brand in sender_name:
                    # It must be exactly "paypal.com" or a subdomain like "mail.paypal.com"
                    is_valid_domain = any(email_domain == domain or email_domain.endswith("." + domain) for domain in allowed_domains)
                    if not is_valid_domain:
                        is_impersonation = True
                        score += 40
                        reasons_found.append(f"Sender claims to be '{brand.capitalize()}', but the email domain ({email_domain}) is not an official {brand.capitalize()} domain.")
                        break
                        
            # 2. Generic Role Impersonation
            if not is_impersonation:
                generic_roles = ["bank", "support", "security", "admin", "service", "it desk"]
                if any(role in sender_name for role in generic_roles) and is_free_provider:
                    is_impersonation = True
                    score += 30
                    reasons_found.append("Sender claims an official title (e.g. Support/Admin) but uses a free email provider.")
                
            is_suspicious_sender = is_impersonation
            
            # --- SUBJECT & CONTENT ANALYSIS ---
            combined_text = f"{subject} {content}"
            
            # 1. Suspicious Links / URLs (Always High Risk)
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd", "buff.ly", "cutt.ly"]
            found_shorteners = [domain for domain in shorteners if domain in combined_text]
            if found_shorteners:
                score += 35
                reasons_found.append(f"Contains URL shorteners often used to hide malicious links: {', '.join(found_shorteners)}.")
            
            ip_urls = re.findall(r'https?://[0-9]+(?:\.[0-9]+){3}', combined_text)
            if ip_urls:
                score += 45
                reasons_found.append("Contains direct IP address links, which is highly suspicious.")

            has_suspicious_links = bool(found_shorteners or ip_urls)

            # --- GOOGLE SAFE BROWSING API CHECK ---
            if SAFE_BROWSING_API_KEY:
                urls_to_check = []
                if email_domain:
                    urls_to_check.append({"url": f"http://{email_domain}"})
                
                # Extract all URLs from the email body
                all_urls = re.findall(r'(https?://[^\s<>"\'\]\[]+)', combined_text + " " + content_html)
                for u in set(all_urls):
                    urls_to_check.append({"url": u})
                
                if urls_to_check:
                    try:
                        sb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
                        sb_payload = {
                            "client": {
                                "clientId": "upwind-email-scorer",
                                "clientVersion": "1.0.0"
                            },
                            "threatInfo": {
                                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                                "platformTypes": ["ANY_PLATFORM"],
                                "threatEntryTypes": ["URL"],
                                "threatEntries": urls_to_check[:500]  # Safe Browsing API limit
                            }
                        }
                        sb_data = json.dumps(sb_payload).encode('utf-8')
                        sb_req = urllib.request.Request(sb_url, data=sb_data, headers={'Content-Type': 'application/json'}, method='POST')
                        
                        with urllib.request.urlopen(sb_req, timeout=3) as sb_response:
                            sb_result = json.loads(sb_response.read().decode('utf-8'))
                            if "matches" in sb_result:
                                matches = sb_result["matches"]
                                bad_urls = set([m["threat"]["url"] for m in matches])
                                score += 100
                                has_suspicious_links = True
                                reasons_found.append(f"Google Safe Browsing flagged dangerous links/domains: {', '.join(bad_urls)}")
                    except Exception as e:
                        pass # Silently fail on network/timeout errors to not break the main flow

            # --- ATTACHMENT & VIRUSTOTAL ANALYSIS ---
            if attachment_hashes and isinstance(attachment_hashes, list):
                dangerous_extensions = ('.exe', '.scr', '.vbs', '.bat', '.cmd', '.js', '.wsf', '.msi', '.ps1', '.jar', '.lnk', '.iso', '.img')
                for attachment in attachment_hashes:
                    file_hash = attachment.get("hash")
                    filename = attachment.get("filename", "Unknown File")
                    
                    # 1. Extension Heuristics
                    if filename.lower().endswith(dangerous_extensions):
                        score += 50
                        reasons_found.append(f"Attachment '{filename}' has a highly dangerous file extension often used to distribute malware.")
                        
                    # 2. Password Protected ZIP Check
                    if "(Password Protected)" in filename:
                        score += 40
                        reasons_found.append(f"Contains a password-protected archive ('{filename.split(' (')[0]}'), which is frequently used to hide malware from scanners.")
                    
                    # 3. VirusTotal Hash Check
                    if not file_hash or not VIRUSTOTAL_API_KEY:
                        continue
                        
                    try:
                        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                        vt_req = urllib.request.Request(vt_url, headers={'x-apikey': VIRUSTOTAL_API_KEY}, method='GET')
                        with urllib.request.urlopen(vt_req, timeout=3) as vt_response:
                            vt_result = json.loads(vt_response.read().decode('utf-8'))
                            stats = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                            malicious_count = stats.get("malicious", 0)
                            
                            if malicious_count > 0:
                                score += 100
                                reasons_found.append(f"VirusTotal detected malware in attachment '{filename}' ({malicious_count} security vendors flagged it).")
                    except urllib.error.HTTPError as e:
                        # 404 means the hash is not in VirusTotal's database (which is normal for clean/new files)
                        pass
                    except Exception as e:
                        pass # Silently fail on network timeouts

            # --- DOMAIN REPUTATION (RDAP AGE CHECK) ---
            if email_domain and not is_free_provider and not is_impersonation:
                try:
                    rdap_url = f"https://rdap.org/domain/{email_domain}"
                    rdap_req = urllib.request.Request(rdap_url, headers={'Accept': 'application/rdap+json'}, method='GET')
                    with urllib.request.urlopen(rdap_req, timeout=3) as rdap_response:
                        rdap_result = json.loads(rdap_response.read().decode('utf-8'))
                        events = rdap_result.get("events", [])
                        for event in events:
                            if event.get("eventAction") == "registration":
                                reg_date_str = event.get("eventDate")
                                if reg_date_str:
                                    reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                                    domain_age_days = (datetime.utcnow() - reg_date).days
                                    if domain_age_days < 30:
                                        score += 60
                                        reasons_found.append(f"Sender domain ({email_domain}) was registered very recently ({domain_age_days} days ago), a massive indicator of a disposable phishing domain.")
                                break
                except Exception as e:
                    pass # Silently fail on network/timeout errors or unsupported TLDs

            # --- SECURITY HEADERS ANALYSIS (SPF/DKIM/DMARC) ---
            if auth_results:
                failed_checks = []
                if "spf=fail" in auth_results or "spf=softfail" in auth_results:
                    failed_checks.append("SPF")
                if "dkim=fail" in auth_results or "dkim=hardfail" in auth_results:
                    failed_checks.append("DKIM")
                if "dmarc=fail" in auth_results:
                    failed_checks.append("DMARC")
                    
                if failed_checks:
                    score += 40
                    reasons_found.append(f"Security header validation failed for {', '.join(failed_checks)}. This strongly suggests the sender domain is being spoofed.")

            # --- DECEPTIVE LINK ANALYSIS (HTML) ---
            if content_html:
                # Find all <a href="url">text</a>
                links = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', content_html, re.IGNORECASE | re.DOTALL)
                for href, text in links:
                    clean_text = re.sub(r'<[^>]+>', '', text).strip().lower()
                    
                    if href.startswith('mailto:') or href.startswith('tel:'):
                        continue
                        
                    # Extract domains for comparison
                    href_domain_match = re.search(r'https?://([^/]+)', href)
                    href_domain = href_domain_match.group(1).lower() if href_domain_match else ""
                    href_domain_clean = re.sub(r'^www\.', '', href_domain)

                    # 1. Explicit URL mismatch (Display text is a URL, but href is different)
                    is_url_display = clean_text.startswith('http') or clean_text.startswith('www.') or ('.' in clean_text and ' ' not in clean_text and len(clean_text) > 4)
                    
                    if is_url_display and href_domain_clean:
                        clean_text_domain = re.sub(r'^https?://', '', clean_text)
                        clean_text_domain = re.sub(r'^www\.', '', clean_text_domain).split('/')[0]
                        
                        # Flag if domains are completely different
                        if clean_text_domain and clean_text_domain not in href_domain_clean and href_domain_clean not in clean_text_domain:
                            score += 50
                            display_text = clean_text[:30] + "..." if len(clean_text) > 30 else clean_text
                            reasons_found.append(f"Contains a deceptive link: The text says '{display_text}' but actually points to '{href_domain_clean}'.")
                            has_suspicious_links = True
                            continue
                            
                    # 2. Brand mismatch (Display text says "Apple" but link goes elsewhere)
                    for brand in brand_domains.keys():
                        if brand in clean_text and href_domain_clean and brand not in href_domain_clean:
                            score += 40
                            reasons_found.append(f"Contains a deceptive '{brand.capitalize()}' link pointing to an unrelated site ({href_domain_clean}).")
                            has_suspicious_links = True
                            break

            # Context: Only penalize business/login keywords heavily if the context is risky
            is_risky_context = is_suspicious_sender or has_suspicious_links

            # 2. Urgency / Threats
            urgency_keywords = ["urgent", "action required", "immediate", "suspended", "verify your account", "locked", "unauthorized access", "validate your account", "within 24 hours", "overdue", "terminate", "דחוף", "פעולה נדרשת", "מיידי", "הושעה", "הושבת", "אמת את החשבון", "ננעל", "גישה בלתי מורשית", "תוך 24 שעות"]
            found_urgency = [word for word in urgency_keywords if word in combined_text]
            if found_urgency:
                if is_risky_context:
                    score += 25
                    reasons_found.append(f"Contains urgency or threat language in a risky context: {', '.join(found_urgency[:3])}.")
                else:
                    score += 5 # Minor penalty for legitimate sources or personal emails using urgency

            # 3. Financial / Payment Requests
            financial_keywords = ["invoice", "payment", "wire transfer", "gift card", "bank account", "billing", "receipt", "bitcoin", "crypto", "unpaid", "חשבונית", "תשלום", "העברה בנקאית", "כרטיס מתנה", "חשבון בנק", "חיוב", "קבלה", "ביטקוין", "קריפטו"]
            found_financial = [word for word in financial_keywords if word in combined_text]
            if found_financial:
                if is_risky_context:
                    score += 20
                    reasons_found.append(f"Contains financial or payment requests from an unverified source: {', '.join(found_financial[:3])}.")
                elif is_free_provider:
                    # Small businesses or friends might send invoices or ask for payment
                    score += 10
                    reasons_found.append(f"Contains financial terms from a free email account: {', '.join(found_financial[:3])}.")
                
                # Even from legit domains or free providers, crypto/wire transfers are red flags
                high_risk_finance = ["bitcoin", "crypto", "wire transfer", "gift card", "ביטקוין", "קריפטו", "העברה בנקאית", "כרטיס מתנה"]
                found_high_risk = [word for word in high_risk_finance if word in combined_text]
                if found_high_risk:
                    score += 30
                    reasons_found.append(f"Requests high-risk payment methods (crypto/wire/gift cards): {', '.join(found_high_risk)}.")

            # 4. Credential Harvesting
            credential_keywords = ["password", "login", "credentials", "authenticate", "click here to login", "reset your password", "sign in", "סיסמה", "סיסמא", "התחברות", "התחבר", "איפוס סיסמה", "איפוס סיסמא", "פרטי התחברות", "כניסה לחשבון"]
            found_credential = [word for word in credential_keywords if word in combined_text]
            if found_credential:
                if is_risky_context or is_free_provider:
                    score += 30
                    reasons_found.append(f"Requests credentials or login actions from an unverified or free account: {', '.join(found_credential[:3])}.")

            # 5. Generic Greetings
            generic_greetings = ["dear customer", "dear user", "dear member", "dear account holder", "dear client", "לקוח יקר", "משתמש יקר", "חבר יקר"]
            found_greetings = [greeting for greeting in generic_greetings if greeting in combined_text]
            if found_greetings and is_risky_context:
                score += 10
                reasons_found.append("Uses a generic greeting instead of a personal name.")

            # Cap the score at 100
            score = min(score, 100)
            
            # Deduplicate reasons while preserving order (same link/pattern in a thread can fire multiple times)
            reasons_found = list(dict.fromkeys(reasons_found))

            # --- DETERMINE VERDICT ---
            if score >= 70:
                verdict = "Highly Suspicious"
            elif score >= 40:
                verdict = "Suspicious"
            elif score >= 15:
                verdict = "Slightly Suspicious"
            else:
                verdict = "Safe"
                
            if not reasons_found:
                reasoning = "The email appears normal and contains no obvious threats."
            else:
                reasoning = " ".join(reasons_found)
                
            # --- AI ANALYSIS (OPTIONAL) ---
            if use_ai:
                if GEMINI_API_KEY:
                    scrubbed_content = scrub_pii(content)
                    
                    metadata_prompt = f"""
                    Act as a Cyber Security Specialist.
                    Analyze this email for phishing/scam risks. You are an independent investigator.
                    Do NOT assume it is safe or malicious, just evaluate the raw data provided.
                    
                    If the SCRUBBED EMAIL CONTENT bearly has data in it and there are no deceptive links or something actual that can harm the user, YOU conclude it is safe and a false positive.
                    
                    Provide a brief 1-2 sentence analysis of the risk level based ONLY on this raw data. At the end of your response, provide your own independent risk score out of 100 (e.g., "AI Risk Score: X/100").
                    
                    --- RAW METADATA ---
                    Email Sent Date: {email_date}
                    Sender: {raw_sender}
                    Subject: {subject}
                    
                    --- SCRUBBED EMAIL CONTENT ---
                    {scrubbed_content[:2000]}
                    """
                    
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
                            
                            payload = {
                                "contents": [{
                                    "parts": [{"text": metadata_prompt}]
                                }]
                            }
                            
                            data = json.dumps(payload).encode('utf-8')
                            
                            headers = {
                                'Content-Type': 'application/json',
                                'x-goog-api-key': GEMINI_API_KEY
                            }
                            
                            req = urllib.request.Request(url, data=data, headers=headers, method='POST')
                            
                            with urllib.request.urlopen(req) as response:
                                result = json.loads(response.read().decode('utf-8'))
                                ai_analysis = result['candidates'][0]['content']['parts'][0]['text'].strip()
                                break # Success, exit retry loop
                                
                        except urllib.error.HTTPError as e:
                            error_body = e.read().decode('utf-8')
                            if e.code == 503 and attempt < max_retries - 1:
                                time.sleep(2) # Wait 2 seconds before retrying
                                continue
                                
                            ai_analysis = f"AI Analysis failed (HTTP {e.code}): {error_body}"
                            break # Exit on non-503 error or final attempt
                        except Exception as e:
                            ai_analysis = f"AI Analysis failed during execution: {str(e)}"
                            break
                else:
                    ai_analysis = f"AI Setup Error:\n{ai_init_error}"
                
        else:
            reasoning = "Error: No email payload received."
            
    except Exception as e:
        score = -1
        verdict = "Error"
        reasoning = f"Failed to process email data: {str(e)}"
        
    # 4. Build the final response object
    response_data = {
        "score": score,
        "verdict": verdict,
        "reasoning": reasoning
    }
    
    if ai_analysis:
        response_data['ai_analysis'] = ai_analysis
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*' 
        },
        'body': json.dumps(response_data)
    }