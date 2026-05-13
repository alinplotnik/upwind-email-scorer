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

    // 3. Packaging the data (The Payload)
    var payload = {
      "sender": sender,
      "subject": subject,
      "content": content,
      "content_html": content_html
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
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/1x/security_black_48dp.png"));

    var section = CardService.newCardSection();

    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Score")
      .setText("<b>" + data.score + " / 100</b>"));

    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Verdict")
      .setText("<b>" + data.verdict + "</b>"));

    section.addWidget(CardService.newTextParagraph()
      .setText("<b>Reasoning:</b><br>" + data.reasoning));

    var aiAction = CardService.newAction().setFunctionName('onAnalyzeWithAI');
    section.addWidget(CardService.newTextButton()
      .setText("Deep Scan with AI")
      .setOnClickAction(aiAction));

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
    
    var payload = {
      "sender": message.getFrom(),
      "subject": message.getSubject(),
      "content": message.getPlainBody(),
      "content_html": message.getBody(),
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
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/1x/memory_black_48dp.png"));

    var section = CardService.newCardSection();
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Score")
      .setText("<b>" + data.score + " / 100</b>"));
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Verdict")
      .setText("<b>" + data.verdict + "</b>"));
    section.addWidget(CardService.newTextParagraph()
      .setText("<b>Reasoning:</b><br>" + data.reasoning));

    if (data.ai_analysis) {
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