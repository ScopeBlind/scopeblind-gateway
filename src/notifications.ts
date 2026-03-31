/**
 * Notification system for protect-mcp approval gates.
 * Sends SMS (Twilio), webhook, or browser push notifications
 * when a tool call requires human approval.
 */

export interface NotificationConfig {
  /** Twilio SMS notification */
  sms?: {
    accountSid: string;
    authToken: string;
    from: string;
    to: string;
  };
  /** Webhook notification (Slack, PagerDuty, custom) */
  webhook?: {
    url: string;
    method?: "POST" | "PUT";
    headers?: Record<string, string>;
    /** Template: 'slack' | 'pagerduty' | 'custom' */
    template?: "slack" | "pagerduty" | "custom";
  };
  /** Email notification */
  email?: {
    to: string;
    /** Uses Resend API if configured, falls back to SMTP */
    resendApiKey?: string;
  };
}

export interface ApprovalNotification {
  requestId: string;
  toolName: string;
  agentId?: string;
  policyName?: string;
  reason: string;
  traceUrl?: string;
  approveUrl?: string;
  timestamp: string;
}

/**
 * Send approval notification through configured channels.
 * Non-blocking — errors are logged, not thrown.
 */
export async function sendApprovalNotification(
  config: NotificationConfig,
  notification: ApprovalNotification,
): Promise<void> {
  const promises: Promise<void>[] = [];

  if (config.sms) {
    promises.push(sendSms(config.sms, notification));
  }
  if (config.webhook) {
    promises.push(sendWebhook(config.webhook, notification));
  }
  if (config.email) {
    promises.push(sendEmail(config.email, notification));
  }

  const results = await Promise.allSettled(promises);
  for (const result of results) {
    if (result.status === "rejected") {
      console.error(`[protect-mcp] Notification failed: ${result.reason}`);
    }
  }
}

/** SMS via Twilio */
async function sendSms(
  config: NonNullable<NotificationConfig["sms"]>,
  notification: ApprovalNotification,
): Promise<void> {
  const body = [
    `🔒 Approval Required`,
    `Tool: ${notification.toolName}`,
    notification.agentId ? `Agent: ${notification.agentId}` : null,
    `Reason: ${notification.reason}`,
    notification.approveUrl ? `Approve: ${notification.approveUrl}` : null,
    notification.traceUrl ? `Trace: ${notification.traceUrl}` : null,
  ].filter(Boolean).join("\n");

  const params = new URLSearchParams({
    To: config.to,
    From: config.from,
    Body: body,
  });

  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${config.accountSid}/Messages.json`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${config.accountSid}:${config.authToken}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    },
  );

  if (!response.ok) {
    throw new Error(`Twilio SMS failed: ${response.status} ${await response.text()}`);
  }
}

/** Webhook (Slack, PagerDuty, custom) */
async function sendWebhook(
  config: NonNullable<NotificationConfig["webhook"]>,
  notification: ApprovalNotification,
): Promise<void> {
  let payload: unknown;

  if (config.template === "slack") {
    payload = {
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: "🔒 Agent Approval Required" },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Tool:*\n\`${notification.toolName}\`` },
            { type: "mrkdwn", text: `*Agent:*\n${notification.agentId || "unknown"}` },
            { type: "mrkdwn", text: `*Policy:*\n${notification.policyName || "default"}` },
            { type: "mrkdwn", text: `*Time:*\n${notification.timestamp}` },
          ],
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: `*Reason:* ${notification.reason}` },
        },
        ...(notification.approveUrl || notification.traceUrl
          ? [
              {
                type: "actions",
                elements: [
                  ...(notification.approveUrl
                    ? [{ type: "button", text: { type: "plain_text", text: "✅ Approve" }, url: notification.approveUrl, style: "primary" }]
                    : []),
                  ...(notification.traceUrl
                    ? [{ type: "button", text: { type: "plain_text", text: "🔍 View Trace" }, url: notification.traceUrl }]
                    : []),
                ],
              },
            ]
          : []),
      ],
    };
  } else if (config.template === "pagerduty") {
    payload = {
      routing_key: config.headers?.["X-Routing-Key"] || "",
      event_action: "trigger",
      payload: {
        summary: `Agent approval required: ${notification.toolName}`,
        source: "protect-mcp",
        severity: "warning",
        custom_details: {
          tool: notification.toolName,
          agent: notification.agentId,
          policy: notification.policyName,
          reason: notification.reason,
          trace_url: notification.traceUrl,
          approve_url: notification.approveUrl,
        },
      },
    };
  } else {
    payload = notification;
  }

  const response = await fetch(config.url, {
    method: config.method || "POST",
    headers: {
      "Content-Type": "application/json",
      ...config.headers,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Webhook failed: ${response.status}`);
  }
}

/** Email via Resend API */
async function sendEmail(
  config: NonNullable<NotificationConfig["email"]>,
  notification: ApprovalNotification,
): Promise<void> {
  if (!config.resendApiKey) {
    console.warn("[protect-mcp] Email notification skipped: no resendApiKey configured");
    return;
  }

  const html = `
    <div style="font-family: monospace; padding: 20px; background: #0d1117; color: #c9d1d9; border-radius: 8px;">
      <h2 style="color: #10b981;">🔒 Agent Approval Required</h2>
      <table style="font-size: 14px; margin: 16px 0;">
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Tool:</td><td>${notification.toolName}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Agent:</td><td>${notification.agentId || "unknown"}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Reason:</td><td>${notification.reason}</td></tr>
        <tr><td style="color: #8b949e; padding: 4px 16px 4px 0;">Time:</td><td>${notification.timestamp}</td></tr>
      </table>
      ${notification.approveUrl ? `<a href="${notification.approveUrl}" style="background: #10b981; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; margin-right: 8px;">✅ Approve</a>` : ""}
      ${notification.traceUrl ? `<a href="${notification.traceUrl}" style="background: #1f2937; color: #c9d1d9; padding: 8px 16px; border-radius: 6px; text-decoration: none; border: 1px solid #374151;">🔍 View Trace</a>` : ""}
    </div>
  `;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.resendApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "ScopeBlind <noreply@scopeblind.com>",
      to: config.to,
      subject: `🔒 Approval required: ${notification.toolName}`,
      html,
    }),
  });

  if (!response.ok) {
    throw new Error(`Resend email failed: ${response.status}`);
  }
}

/**
 * Parse notification config from environment variables.
 * SCOPEBLIND_SMS_TO, SCOPEBLIND_TWILIO_SID, etc.
 */
export function parseNotificationConfigFromEnv(): NotificationConfig | null {
  const config: NotificationConfig = {};
  let hasConfig = false;

  // SMS
  const smsTo = process.env.SCOPEBLIND_SMS_TO;
  const twilioSid = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioFrom = process.env.TWILIO_FROM_NUMBER;
  if (smsTo && twilioSid && twilioToken && twilioFrom) {
    config.sms = { accountSid: twilioSid, authToken: twilioToken, from: twilioFrom, to: smsTo };
    hasConfig = true;
  }

  // Webhook
  const webhookUrl = process.env.SCOPEBLIND_WEBHOOK_URL;
  if (webhookUrl) {
    config.webhook = {
      url: webhookUrl,
      template: (process.env.SCOPEBLIND_WEBHOOK_TEMPLATE as "slack" | "pagerduty" | "custom") || "custom",
    };
    hasConfig = true;
  }

  // Email
  const emailTo = process.env.SCOPEBLIND_EMAIL_TO;
  if (emailTo) {
    config.email = { to: emailTo, resendApiKey: process.env.RESEND_API_KEY };
    hasConfig = true;
  }

  return hasConfig ? config : null;
}
