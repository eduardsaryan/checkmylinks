// auth.js - Enhanced authentication module
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class AuthService {
    constructor(pool, resendClient) {
        this.pool = pool;
        this.resend = resendClient;
    }

    // Generate JWT token
    generateToken(userId, email) {
        return jwt.sign(
            { id: userId, email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
    }

    // Generate secure random token
    generateSecureToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    // Register new user
    async register(name, email, password) {
        try {
            // Check if user exists
            const existingUser = await this.pool.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );

            if (existingUser.rows.length > 0) {
                throw new Error('Email already registered');
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Create user
            const result = await this.pool.query(
                `INSERT INTO users (name, email, password, plan, plan_limit) 
                 VALUES ($1, $2, $3, 'free', 100) 
                 RETURNING id, name, email, plan`,
                [name, email, hashedPassword]
            );

            const user = result.rows[0];
            const token = this.generateToken(user.id, user.email);

            // Send welcome email
            await this.sendWelcomeEmail(email, name);

            return {
                success: true,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    plan: user.plan
                },
                token
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Login user
    async login(email, password, ipAddress = null, userAgent = null) {
        try {
            // Get user
            const result = await this.pool.query(
                'SELECT id, name, email, password, plan, plan_limit, scans_this_month FROM users WHERE email = $1',
                [email]
            );

            if (result.rows.length === 0) {
                throw new Error('Invalid credentials');
            }

            const user = result.rows[0];

            // Verify password
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                throw new Error('Invalid credentials');
            }

            // Generate token
            const token = this.generateToken(user.id, user.email);

            // Store session
            await this.createSession(user.id, token, ipAddress, userAgent);

            return {
                success: true,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    plan: user.plan,
                    planLimit: user.plan_limit,
                    scansThisMonth: user.scans_this_month
                },
                token
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Create user session
    async createSession(userId, token, ipAddress, userAgent) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

        await this.pool.query(
            `INSERT INTO user_sessions (user_id, token, ip_address, user_agent, expires_at)
             VALUES ($1, $2, $3, $4, $5)`,
            [userId, token, ipAddress, userAgent, expiresAt]
        );
    }

    // Verify token and get user
    async verifyToken(token) {
        try {
            // Verify JWT
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // Check if session exists and is valid
            const sessionResult = await this.pool.query(
                `SELECT s.*, u.id, u.name, u.email, u.plan, u.plan_limit, u.scans_this_month
                 FROM user_sessions s
                 JOIN users u ON s.user_id = u.id
                 WHERE s.token = $1 AND s.expires_at > NOW()`,
                [token]
            );

            if (sessionResult.rows.length === 0) {
                throw new Error('Invalid or expired session');
            }

            const user = sessionResult.rows[0];
            return {
                success: true,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    plan: user.plan,
                    planLimit: user.plan_limit,
                    scansThisMonth: user.scans_this_month
                }
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Request password reset
    async requestPasswordReset(email) {
        try {
            const userResult = await this.pool.query(
                'SELECT id, name FROM users WHERE email = $1',
                [email]
            );

            if (userResult.rows.length === 0) {
                // Don't reveal if email exists
                return { success: true };
            }

            const user = userResult.rows[0];
            const resetToken = this.generateSecureToken();
            const expiresAt = new Date();
            expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour

            // Store reset token
            await this.pool.query(
                'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
                [resetToken, expiresAt, user.id]
            );

            // Send reset email
            await this.sendPasswordResetEmail(email, user.name, resetToken);

            return { success: true };
        } catch (error) {
            return {
                success: false,
                error: 'Failed to process request'
            };
        }
    }

    // Reset password
    async resetPassword(token, newPassword) {
        try {
            const userResult = await this.pool.query(
                'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
                [token]
            );

            if (userResult.rows.length === 0) {
                throw new Error('Invalid or expired reset token');
            }

            const userId = userResult.rows[0].id;
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            // Update password and clear reset token
            await this.pool.query(
                'UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
                [hashedPassword, userId]
            );

            return { success: true };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Logout (invalidate session)
    async logout(token) {
        try {
            await this.pool.query(
                'DELETE FROM user_sessions WHERE token = $1',
                [token]
            );
            return { success: true };
        } catch (error) {
            return {
                success: false,
                error: 'Failed to logout'
            };
        }
    }

    // Clean expired sessions
    async cleanExpiredSessions() {
        await this.pool.query(
            'DELETE FROM user_sessions WHERE expires_at < NOW()'
        );
    }

    // Email functions
    async sendWelcomeEmail(email, name) {
        if (!this.resend) return;

        try {
            await this.resend.emails.send({
                from: 'CheckMyLinks <noreply@checkmylinks.io>',
                to: email,
                subject: 'Welcome to CheckMyLinks!',
                html: `
                    <h2>Welcome to CheckMyLinks, ${name}!</h2>
                    <p>Thank you for signing up. You can now start checking your website for broken links.</p>
                    <p>Your free plan includes:</p>
                    <ul>
                        <li>100 scans per month</li>
                        <li>Up to 500 links per scan</li>
                        <li>Email notifications</li>
                        <li>CSV exports</li>
                    </ul>
                    <p><a href="https://checkmylinks.io" style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Start Scanning</a></p>
                    <p>Best regards,<br>The CheckMyLinks Team</p>
                `
            });
        } catch (error) {
            console.error('Failed to send welcome email:', error);
        }
    }

    async sendPasswordResetEmail(email, name, token) {
        if (!this.resend) return;

        const resetUrl = `https://checkmylinks.io/reset-password?token=${token}`;

        try {
            await this.resend.emails.send({
                from: 'CheckMyLinks <noreply@checkmylinks.io>',
                to: email,
                subject: 'Reset Your Password',
                html: `
                    <h2>Hi ${name},</h2>
                    <p>You requested to reset your password. Click the link below to create a new password:</p>
                    <p><a href="${resetUrl}" style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                    <p>Best regards,<br>The CheckMyLinks Team</p>
                `
            });
        } catch (error) {
            console.error('Failed to send reset email:', error);
        }
    }
}

module.exports = AuthService;