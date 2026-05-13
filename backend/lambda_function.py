import google.generativeai as genai
import json
import re
import os

# Configure the AI securely
model = None
if "GEMINI_API_KEY" in os.environ:
    genai.configure(api_key=os.environ["GEMINI_API_KEY"])
    model = genai.GenerativeModel('gemini-1.5-flash')

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
            
            # --- SENDER ANALYSIS ---
            # Extract email address if format is "Name <email@domain.com>"
            email_address = sender
            email_match = re.search(r'<([^>]+)>', sender)
            sender_name = sender
            if email_match:
                email_address = email_match.group(1)
                sender_name = sender.replace(f"<{email_address}>", "").strip().strip('"').strip("'")
            
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
                            reasons_found.append(f"Contains a deceptive link: The text says '{clean_text}' but actually points to '{href_domain_clean}'.")
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
            urgency_keywords = ["urgent", "action required", "immediate", "suspended", "verify your account", "locked", "unauthorized access", "validate your account", "within 24 hours", "overdue", "terminate"]
            found_urgency = [word for word in urgency_keywords if word in combined_text]
            if found_urgency:
                if is_risky_context:
                    score += 25
                    reasons_found.append(f"Contains urgency or threat language in a risky context: {', '.join(found_urgency[:3])}.")
                else:
                    score += 5 # Minor penalty for legitimate sources or personal emails using urgency

            # 3. Financial / Payment Requests
            financial_keywords = ["invoice", "payment", "wire transfer", "gift card", "bank account", "billing", "receipt", "bitcoin", "crypto", "unpaid"]
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
                high_risk_finance = ["bitcoin", "crypto", "wire transfer", "gift card"]
                found_high_risk = [word for word in high_risk_finance if word in combined_text]
                if found_high_risk:
                    score += 30
                    reasons_found.append(f"Requests high-risk payment methods (crypto/wire/gift cards): {', '.join(found_high_risk)}.")

            # 4. Credential Harvesting
            credential_keywords = ["password", "login", "credentials", "authenticate", "click here to login", "reset your password", "sign in"]
            found_credential = [word for word in credential_keywords if word in combined_text]
            if found_credential:
                if is_risky_context or is_free_provider:
                    score += 30
                    reasons_found.append(f"Requests credentials or login actions from an unverified or free account: {', '.join(found_credential[:3])}.")

            # 5. Generic Greetings
            generic_greetings = ["dear customer", "dear user", "dear member", "dear account holder", "dear client"]
            found_greetings = [greeting for greeting in generic_greetings if greeting in combined_text]
            if found_greetings and is_risky_context:
                score += 10
                reasons_found.append("Uses a generic greeting instead of a personal name.")

            # Cap the score at 100
            score = min(score, 100)

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
            if use_ai and model:
                metadata_prompt = f"""
                Act as a Cyber Security Specialist.
                Analyze this email metadata for phishing/scam risks. 
                Do NOT assume it is safe or malicious, just evaluate the signals.
                Provide a brief 1-2 sentence analysis of the risk level based ONLY on this metadata.
                
                Sender: {raw_sender}
                Subject: {subject}
                Is Free Provider: {is_free_provider}
                Sender Mismatch (Impersonation Risk): {is_impersonation}
                Contains Deceptive Links or IPs: {has_suspicious_links}
                Risk Flags Found by Heuristics: {', '.join(reasons_found) if reasons_found else 'None'}
                Calculated Heuristic Score: {score}/100
                """
                try:
                    response = model.generate_content(metadata_prompt)
                    ai_analysis = response.text.strip()
                except Exception as e:
                    ai_analysis = f"AI Analysis failed: {str(e)}"
                
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