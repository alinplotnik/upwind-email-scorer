import json

def lambda_handler(event, context):
    # Default values in case the email is safe or data is missing
    score = 0
    verdict = "Safe"
    reasoning = "The email appears normal and contains no obvious threats."
    
    try:
        # 1. Extract the payload sent by the Gmail Add-on
        if 'body' in event:
            body = json.loads(event['body'])
            sender = body.get('sender', '').lower()
            subject = body.get('subject', '').lower()
            content = body.get('content', '').lower()
            
            # 2. Basic Analysis (Signals)
            reasons_found = []
            
            # Check for psychological manipulation/urgency keywords
            suspicious_keywords = ["urgent", "password", "invoice", "suspended", "action required"]
            found_keywords = [word for word in suspicious_keywords if word in content or word in subject]
            
            if found_keywords:
                score += 45
                reasons_found.append(f"Contains suspicious keywords: {', '.join(found_keywords)}.")
            
            # Check sender domain (basic check for free providers)
            free_providers = ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]
            if any(provider in sender for provider in free_providers):
                score += 25
                reasons_found.append("Email originates from a free, public email provider.")
                
            # 3. Determine the final verdict based on the score
            if score >= 70:
                verdict = "Highly Suspicious"
            elif score >= 40:
                verdict = "Suspicious"
                
            # Update reasoning if we found anything
            if reasons_found:
                reasoning = " ".join(reasons_found)
                
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
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*' 
        },
        'body': json.dumps(response_data)
    }