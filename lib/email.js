// lib/email.js - Email service
class EmailService {
    constructor(resendClient) {
        this.resend = resendClient;
    }

    async sendScanCompleteEmail(email, name, scanUrl, brokenLinks, totalLinks) {
        if (!this.resend) return;

        try {
            await this.resend.emails.send({
                from: 'CheckMyLinks <noreply@checkmylinks.io>',
                to: email,
                subject: `Scan Complete: ${new URL(scanUrl).hostname}`,
                html: `
                    <h2>Hi ${name},</h2>
                    <p>Your link scan for <strong>${scanUrl}</strong> is complete!</p>
                    <div style="background: #f3f4f6; padding: 20px; border-radius: 5px; margin: 20px 0;">
                        <h3 style="margin-top: 0;">Scan Results:</h3>
                        <p><strong>Total Links Checked:</strong> ${totalLinks}</p>
                        <p><strong>Broken Links Found:</strong> <span style="color: ${brokenLinks > 0 ? '#ef4444' : '#10b981'};">${brokenLinks}</span></p>
                    </div>
                    <p><a href="https://checkmylinks.io/dashboard" style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Full Report</a></p>
                    <p>Best regards,<br>The CheckMyLinks Team</p>
                `
            });
        } catch (error) {
            console.error('Failed to send scan complete email:', error);
        }
    }

    async sendPlanLimitWarning(email, name, scansUsed, planLimit) {
        if (!this.resend) return;

        const percentUsed = Math.round((scansUsed / planLimit) * 100);

        try {
            await this.resend.emails.send({
                from: 'CheckMyLinks <noreply@checkmylinks.io>',
                to: email,
                subject: 'Approaching Scan Limit',
                html: `
                    <h2>Hi ${name},</h2>
                    <p>You've used <strong>${scansUsed} of ${planLimit}</strong> scans (${percentUsed}%) this month.</p>
                    <p>Consider upgrading your plan for unlimited scans and additional features:</p>
                    <ul>
                        <li>Unlimited monthly scans</li>
                        <li>Scheduled scans</li>
                        <li>Priority support</li>
                        <li>Advanced reporting</li>
                    </ul>
                    <p><a href="https://checkmylinks.io/#pricing" style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Upgrade Now</a></p>
                    <p>Best regards,<br>The CheckMyLinks Team</p>
                `
            });
        } catch (error) {
            console.error('Failed to send limit warning email:', error);
        }
    }
}

module.exports = EmailService;