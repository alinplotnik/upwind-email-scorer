function getHexHash(bytes) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  var hexHash = '';
  for (var j = 0; j < digest.length; j++) {
    var byteValue = digest[j];
    if (byteValue < 0) byteValue += 256;
    var hexString = byteValue.toString(16);
    if (hexString.length == 1) hexString = '0' + hexString;
    hexHash += hexString;
  }
  return hexHash;
}

function processBlob(blob, filename, attachment_hashes) {
  try {
    // Hash the current file (either the main attachment or an inner unzipped file)
    attachment_hashes.push({
      "filename": filename,
      "hash": getHexHash(blob.getBytes())
    });
    
    // If it's a zip file, try to unpack it and process its contents
    if (filename.toLowerCase().slice(-4) === '.zip') {
      try {
        var unzippedBlobs = Utilities.unzip(blob);
        for (var k = 0; k < unzippedBlobs.length; k++) {
          var innerBlob = unzippedBlobs[k];
          var innerFilename = filename + " -> " + innerBlob.getName();
          // Recursively process the inner file (in case there's a zip inside a zip!)
          processBlob(innerBlob, innerFilename, attachment_hashes);
        }
      } catch (e) {
        // If unzipping fails, it is likely a password-protected zip file
        attachment_hashes.push({
          "filename": filename + " (Password Protected)",
          "hash": ""
        });
      }
    }
  } catch (globalBlobError) {
    // Failsafe: If reading the blob or hashing fails entirely (e.g., file too large/corrupted), 
    // simply log it as unhashable so the rest of the email scan still works.
    attachment_hashes.push({
      "filename": filename + " (Unhashable/Error)",
      "hash": ""
    });
  }
}

/**
 * Computes SHA-256 hashes for all attachments and extracts ZIP files.
 */
function getAttachmentHashes(message) {
  var attachments = message.getAttachments();
  var attachment_hashes = [];
  
  for (var i = 0; i < attachments.length; i++) {
    var attachment = attachments[i];
    processBlob(attachment, attachment.getName(), attachment_hashes);
  }
  return attachment_hashes;
}

/**
 * This function is triggered automatically every time a user opens an email.
 */
function onGmailMessageOpen(e) {
  // 1.AWS Backend URL
  var awsLambdaUrl = "https://ybop6lve2kkvidb44fvb7dsl3y0ofjjt.lambda-url.eu-north-1.on.aws/";

  try {
    // 2. Extracting the real email data using Gmail API
    // Get the temporary access token and message ID from the event object
    var accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    var messageId = e.gmail.messageId;
    
    // Fetch the actual message
    var message = GmailApp.getMessageById(messageId);
    var sender = message.getFrom();
    var subject = message.getSubject();
    var content = message.getPlainBody();
    var content_html = message.getBody();
    var attachment_hashes = getAttachmentHashes(message);
    var email_date = message.getDate().toString();
    
    // Extract Authentication-Results header securely
    var rawContent = message.getRawContent();
    var headersPart = rawContent.split('\r\n\r\n')[0]; 
    var authMatch = headersPart.match(/^Authentication-Results:([\s\S]*?)(?=\r\n[A-Za-z0-9-]+:|\r\n$|$)/m);
    var auth_results = authMatch ? authMatch[1].replace(/\r\n\s+/g, ' ').trim() : "";

    // 3. Packaging the data (The Payload)
    var payload = {
      "sender": sender,
      "subject": subject,
      "content": content,
      "content_html": content_html,
      "user_email": Session.getEffectiveUser().getEmail(),
      "attachment_hashes": attachment_hashes,
      "email_date": email_date,
      "auth_results": auth_results
    };

    // 4. Sending the POST request to AWS Lambda
    var options = {
      'method': 'post',
      'contentType': 'application/json',
      'payload': JSON.stringify(payload),
      'muteHttpExceptions': true
    };
    
    var response = UrlFetchApp.fetch(awsLambdaUrl, options);
    var data = JSON.parse(response.getContentText());

    // 5. Building the Add-on UI using CardService
    var card = CardService.newCardBuilder();
    
    card.setHeader(CardService.newCardHeader()
      .setTitle("Upwind Security Scan")
      .setImageUrl("https://raw.githubusercontent.com/alinplotnik/upwind-email-scorer/refs/heads/main/upwind.jpg"));

    var section = CardService.newCardSection();

    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Score")
      .setText("<span dir=\"ltr\" style=\"text-align:left;direction:ltr;\"><b>" + data.score + " / 100</b></span>"));

    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Verdict")
      .setText("<span dir=\"ltr\" style=\"text-align:left;direction:ltr;\"><b>" + data.verdict + "</b></span>"));

    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Reasoning")
      .setText("<b>" + data.reasoning + "</b>")
      .setWrapText(true));

    if (data.reasoning !== "You sent this email to yourself.") {
      // Spacer
      section.addWidget(CardService.newTextParagraph().setText(" "));
      
      var aiAction = CardService.newAction().setFunctionName('onAnalyzeWithAI');
      section.addWidget(CardService.newTextButton()
        .setText("🔍  Deep Scan with AI")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setBackgroundColor('#6B21A8')
        .setOnClickAction(aiAction));
  
      section.addWidget(CardService.newTextParagraph()
        .setText("<div dir='ltr'><font color='#757575'><i>Note: Deep Scan sends a privacy-safe version of this email to Gemini AI. Personal identifiers (phone numbers, ID numbers, credit card numbers) are automatically redacted before sending.</i></font></div>"));
    }

    card.addSection(section);

    return card.build();

  } catch (error) {
    // Error handling
    var errorCard = CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Error"))
      .addSection(CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText("Failed to process email.<br><br>Details: " + error.toString())))
      .build();
    return errorCard;
  }
}

function onAnalyzeWithAI(e) {
  var awsLambdaUrl = "https://ybop6lve2kkvidb44fvb7dsl3y0ofjjt.lambda-url.eu-north-1.on.aws/";
  try {
    var accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    var messageId = e.gmail.messageId;
    var message = GmailApp.getMessageById(messageId);
    
    var rawContent = message.getRawContent();
    var headersPart = rawContent.split('\r\n\r\n')[0]; 
    var authMatch = headersPart.match(/^Authentication-Results:([\s\S]*?)(?=\r\n[A-Za-z0-9-]+:|\r\n$|$)/m);
    var auth_results = authMatch ? authMatch[1].replace(/\r\n\s+/g, ' ').trim() : "";
    
    var payload = {
      "sender": message.getFrom(),
      "subject": message.getSubject(),
      "content": message.getPlainBody(),
      "content_html": message.getBody(),
      "user_email": Session.getEffectiveUser().getEmail(),
      "attachment_hashes": getAttachmentHashes(message),
      "email_date": message.getDate().toString(),
      "auth_results": auth_results,
      "use_ai": true
    };

    var options = {
      'method': 'post',
      'contentType': 'application/json',
      'payload': JSON.stringify(payload),
      'muteHttpExceptions': true
    };
    
    var response = UrlFetchApp.fetch(awsLambdaUrl, options);
    var data = JSON.parse(response.getContentText());

    var card = CardService.newCardBuilder();
    card.setHeader(CardService.newCardHeader()
      .setTitle("Upwind AI Security Scan")
      .setImageUrl("https://raw.githubusercontent.com/alinplotnik/upwind-email-scorer/refs/heads/main/upwind.jpg"));

    var section = CardService.newCardSection();
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Score")
      .setText("<b>" + data.score + " / 100</b>"));
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Verdict")
      .setText("<b>" + data.verdict + "</b>"));
    section.addWidget(CardService.newTextParagraph()
      .setText("<b>Reasoning:</b><br>" + data.reasoning));

    if (data.verdict === "🏄‍♂️ UPWIND VIP 🏄‍♀️") {
        section.addWidget(CardService.newImage()
          .setImageUrl("https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExNWg2NXl6cWVqdGQ3c3N5YmoxdnQ1amZtYXk5cGhqb2VlZWFhMGV1YiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/PxkenUJZIeUPIFschq/giphy.gif")
          .setAltText("cyber shaka"));
        if (data.ai_analysis) {
            section.addWidget(CardService.newTextParagraph()
              .setText("<b>AI Analysis:</b><br>" + data.ai_analysis));
        }
    } else if (data.ai_analysis) {
        section.addWidget(CardService.newTextParagraph()
          .setText("<b>AI Analysis:</b><br>" + data.ai_analysis));
    }

    card.addSection(section);
    
    var nav = CardService.newNavigation().pushCard(card.build());
    return CardService.newActionResponseBuilder().setNavigation(nav).build();

  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Failed to analyze with AI: " + error.toString()))
      .build();
  }
}