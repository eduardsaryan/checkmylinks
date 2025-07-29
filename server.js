const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const Bull = require('bull');
const Redis = require('redis');
const { Resend } = require('resend');
const AuthService = require('./lib/auth');
const dashboardRoutes = require('./routes/dashboard');
const scanRoutes = require('./routes/scans');
const cheerio = require('cheerio');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disable for development
}));
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json());

// Serve static files
app.use(express.static('.'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api', limiter);

// Database connection
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'checkmylinks',
    password: process.env.DB_PASSWORD || 'password',
    port: process.env.DB_PORT || 5432,
});

// Redis connection
let redisClient;
try {
    redisClient = Redis.createClient({
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
    });
    
    redisClient.on('error', (err) => {
        console.error('Redis Client Error:', err);
    });
    
    redisClient.on('connect', () => {
        console.log('Redis connected successfully');
    });
} catch (error) {
    console.error('Redis connection failed:', error);
}

// Initialize services
const resend = new Resend(process.env.RESEND_API_KEY);
const authService = new AuthService(pool, resend);

// Queue for link checking
const linkQueue = new Bull('link-checking', {
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
    },
    defaultJobOptions: {
        attempts: 3,
        backoff: {
            type: 'exponential',
            delay: 2000,
        },
        removeOnComplete: 10,
        removeOnFail: 5,
    }
});

// Add queue event listeners
linkQueue.on('completed', (job, result) => {
    console.log(`Job ${job.id} completed successfully`);
});

linkQueue.on('failed', (job, err) => {
    console.error(`Job ${job.id} failed:`, err.message);
});

linkQueue.on('active', (job) => {
    console.log(`Job ${job.id} is now active`);
});

linkQueue.on('waiting', (jobId) => {
    console.log(`Job ${jobId} is waiting`);
});

// Helper functions
async function checkLink(url) {
    try {
        const response = await axios.head(url, {
            timeout: 10000,
            validateStatus: () => true,
            maxRedirects: 5,
            headers: {
                'User-Agent': 'CheckMyLinks Bot 1.0 (Link Checker)'
            }
        });
        return {
            url,
            status: response.status,
            error: null
        };
    } catch (error) {
        // Try GET request if HEAD fails
        try {
            const response = await axios.get(url, {
                timeout: 10000,
                validateStatus: () => true,
                maxRedirects: 5,
                maxContentLength: 1024 * 1024, // 1MB limit
                headers: {
                    'User-Agent': 'CheckMyLinks Bot 1.0 (Link Checker)'
                }
            });
            return {
                url,
                status: response.status,
                error: null
            };
        } catch (getError) {
            return {
                url,
                status: null,
                error: getError.code || getError.message
            };
        }
    }
}

async function extractLinks(url) {
    try {
        const response = await axios.get(url, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'CheckMyLinks Bot 1.0 (Link Checker)'
            }
        });
        const $ = cheerio.load(response.data);
        const links = new Set();
        
        $('a[href]').each((i, elem) => {
            let href = $(elem).attr('href');
            
            if (!href) return;
            
            // Skip non-http links
            if (href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('#')) {
                return;
            }
            
            if (href.startsWith('/')) {
                const baseUrl = new URL(url);
                href = `${baseUrl.protocol}//${baseUrl.host}${href}`;
            } else if (!href.startsWith('http')) {
                return;
            }
            
            try {
                new URL(href); // Validate URL
                links.add(href);
            } catch (e) {
                // Skip invalid URLs
            }
        });
        
        return Array.from(links);
    } catch (error) {
        throw new Error(`Failed to extract links: ${error.message}`);
    }
}

// Add services to request
app.use((req, res, next) => {
    req.pool = pool;
    req.authService = authService;
    next();
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'CheckMyLinks' });
});

// Auth endpoints
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const result = await authService.register(name, email, password);
    
    if (result.success) {
        res.json({
            token: result.token,
            user: result.user
        });
    } else {
        res.status(400).json({ error: result.error });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const result = await authService.login(email, password, ipAddress, userAgent);
    
    if (result.success) {
        res.json({
            token: result.token,
            user: result.user
        });
    } else {
        res.status(401).json({ error: result.error });
    }
});

app.post('/api/auth/logout', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (token) {
        await authService.logout(token);
    }
    
    res.json({ success: true, message: 'Logged out successfully' });
});

// Verify email
app.get('/api/auth/verify-email', async (req, res) => {
    const { token } = req.query;
    
    if (!token) {
        return res.status(400).json({ error: 'Verification token required' });
    }
    
    const result = await authService.verifyEmail(token);
    
    if (result.success) {
        res.send(`
            <html>
                <head>
                    <title>Email Verified - CheckMyLinks</title>
                    <meta http-equiv="refresh" content="3;url=/">
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .success { color: #10b981; }
                        .countdown { color: #6b7280; font-size: 0.9em; }
                    </style>
                </head>
                <body>
                    <h1 class="success">✓ Email Verified Successfully!</h1>
                    <p>Your email has been verified. You can now access all features.</p>
                    <p class="countdown">Redirecting in a few seconds...</p>
                    <p><a href="/">Click here if not redirected automatically</a></p>
                </body>
            </html>
        `);
    } else {
        res.redirect('/?verification_failed=true');
    }
});

// Dashboard stats endpoint
app.get('/api/scans/stats', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const authResult = await authService.verifyToken(token);
    
    if (!authResult.success) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    try {
        const userId = authResult.user.id;
        const currentMonth = new Date();
        currentMonth.setDate(1);
        currentMonth.setHours(0, 0, 0, 0);
        
        // Total scans for user
        const totalScansResult = await pool.query(
            'SELECT COUNT(*) as count FROM scans WHERE user_id = $1',
            [userId]
        );
        
        // Monthly scans for user
        const monthlyScansResult = await pool.query(
            'SELECT COUNT(*) as count FROM scans WHERE user_id = $1 AND created_at >= $2',
            [userId, currentMonth]
        );
        
        // Total broken links found
        const totalBrokenLinksResult = await pool.query(`
            SELECT SUM(s.broken_links) as total 
            FROM scans s 
            WHERE s.user_id = $1 AND s.status = 'completed' AND s.broken_links IS NOT NULL
        `, [userId]);
        
        // Monthly broken links found
        const monthlyBrokenLinksResult = await pool.query(`
            SELECT SUM(s.broken_links) as total 
            FROM scans s 
            WHERE s.user_id = $1 AND s.status = 'completed' AND s.created_at >= $2 AND s.broken_links IS NOT NULL
        `, [userId, currentMonth]);
        
        // Get last scan date
        const lastScanResult = await pool.query(
            'SELECT created_at FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
            [userId]
        );
        
        res.json({
            totalScans: parseInt(totalScansResult.rows[0].count) || 0,
            monthlyScans: parseInt(monthlyScansResult.rows[0].count) || 0,
            totalBrokenLinks: parseInt(totalBrokenLinksResult.rows[0].total) || 0,
            monthlyBrokenLinks: parseInt(monthlyBrokenLinksResult.rows[0].total) || 0,
            lastScan: lastScanResult.rows[0]?.created_at || null
        });
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Resend verification email
app.post('/api/auth/resend-verification', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const authResult = await authService.verifyToken(token);
    
    if (!authResult.success) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    const result = await authService.resendVerificationEmail(authResult.user.id);
    res.json(result);
});

// Dashboard routes
app.use('/api', dashboardRoutes);

// Scan routes - Pass all required dependencies
app.use('/api/scans', scanRoutes(pool, linkQueue, authService));

// Public scan endpoint
app.post('/api/public/scan', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }
        
        try {
            new URL(url);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid URL' });
        }
        
        console.log(`Starting public scan for: ${url}`);
        
        const links = await extractLinks(url);
        console.log(`Extracted ${links.length} links`);
        
        const limitedLinks = links.slice(0, 50);
        
        const results = [];
        for (const link of limitedLinks) {
            try {
                const result = await checkLink(link);
                results.push({
                    ...result,
                    foundOn: url
                });
            } catch (error) {
                console.error(`Error checking link ${link}:`, error);
                results.push({
                    url: link,
                    status: null,
                    error: error.message,
                    foundOn: url
                });
            }
        }
        
        const stats = {
            total: results.length,
            broken: results.filter(r => !r.status || r.status >= 400).length,
            ok: results.filter(r => r.status && r.status < 400).length,
            redirects: results.filter(r => r.status && (r.status === 301 || r.status === 302)).length
        };
        
        console.log(`Scan completed. Stats:`, stats);
        
        res.json({
            url,
            stats,
            results: results.filter(r => !r.status || r.status >= 400), // Only return broken links
            limited: links.length > 50,
            message: links.length > 50 ? 'Showing first 50 links. Sign up for full scan.' : null
        });
    } catch (error) {
        console.error('Public scan error:', error);
        res.status(500).json({ error: `Scan failed: ${error.message}` });
    }
});

// Queue processor - IMPORTANT: This must be defined BEFORE routes that add jobs
linkQueue.process('scan-website', async (job) => {
    const { scanId, url, userId } = job.data;
    
    try {
        console.log(`[QUEUE] Processing scan ${scanId} for URL: ${url}`);
        
        // Update scan status to processing
        await pool.query(
            'UPDATE scans SET status = $1 WHERE id = $2', 
            ['processing', scanId]
        );
        
        console.log(`[QUEUE] Updated scan ${scanId} status to processing`);
        
        // Extract links from the website
        console.log(`[QUEUE] Extracting links from ${url}`);
        const links = await extractLinks(url);
        console.log(`[QUEUE] Extracted ${links.length} links for scan ${scanId}`);
        
        const results = [];
        let processedCount = 0;
        
        // Process links in batches to avoid overwhelming the target server
        const batchSize = 5;
        for (let i = 0; i < links.length; i += batchSize) {
            const batch = links.slice(i, i + batchSize);
            
            const batchPromises = batch.map(async (link) => {
                try {
                    const result = await checkLink(link);
                    processedCount++;
                    
                    if (processedCount % 10 === 0) {
                        console.log(`[QUEUE] Processed ${processedCount}/${links.length} links for scan ${scanId}`);
                    }
                    
                    results.push({
                        ...result,
                        foundOn: url
                    });
                    
                    // Insert scan result into database
                    await pool.query(
                        'INSERT INTO scan_results (scan_id, url, status_code, found_on, error_message) VALUES ($1, $2, $3, $4, $5)',
                        [scanId, result.url, result.status, url, result.error]
                    );
                    
                    return result;
                } catch (error) {
                    console.error(`[QUEUE] Error checking link ${link} in scan ${scanId}:`, error);
                    
                    // Still insert the failed result
                    await pool.query(
                        'INSERT INTO scan_results (scan_id, url, status_code, found_on, error_message) VALUES ($1, $2, $3, $4, $5)',
                        [scanId, link, null, url, error.message]
                    );
                    
                    return { url: link, status: null, error: error.message };
                }
            });
            
            await Promise.all(batchPromises);
            
            // Small delay between batches
            if (i + batchSize < links.length) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
        
        const brokenCount = results.filter(r => !r.status || r.status >= 400).length;
        
        // Update scan with final results
        await pool.query(
            'UPDATE scans SET status = $1, total_links = $2, broken_links = $3, completed_at = CURRENT_TIMESTAMP WHERE id = $4',
            ['completed', links.length, brokenCount, scanId]
        );
        
        console.log(`[QUEUE] Scan ${scanId} completed successfully. Total: ${links.length}, Broken: ${brokenCount}`);
        
        return { 
            scanId, 
            totalLinks: links.length, 
            brokenLinks: brokenCount,
            results: results.filter(r => !r.status || r.status >= 400) // Only broken links
        };
        
    } catch (error) {
        console.error(`[QUEUE] Scan ${scanId} failed:`, error);
        
        // Update scan status to failed
        await pool.query(
            'UPDATE scans SET status = $1 WHERE id = $2',
            ['failed', scanId]
        );
        
        throw error;
    }
});

// Database initialization
const createTables = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                plan VARCHAR(50) DEFAULT 'free',
                plan_limit INTEGER DEFAULT 5,
                scans_this_month INTEGER DEFAULT 0,
                email_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                url VARCHAR(1000) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                total_links INTEGER DEFAULT 0,
                broken_links INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS scan_results (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id),
                url VARCHAR(1000) NOT NULL,
                status_code INTEGER,
                found_on VARCHAR(1000),
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Database tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
    }
};

// Serve static files (your HTML)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Catch-all handler for SPA (should be last)
app.get('*', (req, res) => {
    // Only serve index.html for non-API routes
    if (!req.path.startsWith('/api')) {
        res.sendFile(path.join(__dirname, 'index.html'));
    } else {
        res.status(404).json({ error: 'API endpoint not found' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;

const startServer = async () => {
    await createTables();
    
    app.listen(PORT, () => {
        console.log(`CheckMyLinks server running on port ${PORT}`);
    });
};

startServer();

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await pool.end();
    redisClient.quit();
    process.exit(0);
});