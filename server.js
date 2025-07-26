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
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json());

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
const redisClient = Redis.createClient({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
});


// Initialize services
const resend = new Resend(process.env.RESEND_API_KEY);
const authService = new AuthService(pool, resend);

// Queue for link checking
const linkQueue = new Bull('link-checking', {
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
    }
});

app.use((req, res, next) => {
    req.pool = pool;
    req.authService = authService;
    next();
});

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
    res.redirect('/?verified=true&message=Your+email+has+been+verified');
    } else {
        res.redirect('/?verification_failed=true');
    }
    
    // if (result.success) {
    //     res.redirect('/?verified=true');
    // } else {
    //     res.redirect('/?verification_failed=true');
    // }
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

// Scan routes
app.use('/api/scans', scanRoutes(pool, linkQueue, authService));

// Public scan endpoint
app.post('/api/public/scan', async (req, res) => {
    try {
        const { url } = req.body;
        
        try {
            new URL(url);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid URL' });
        }
        
        const links = await extractLinks(url);
        const limitedLinks = links.slice(0, 50);
        
        const results = [];
        for (const link of limitedLinks) {
            const result = await checkLink(link);
            results.push({
                ...result,
                foundOn: url
            });
        }
        
        const stats = {
            total: results.length,
            broken: results.filter(r => !r.status || r.status >= 400).length,
            ok: results.filter(r => r.status && r.status < 400).length,
            redirects: results.filter(r => r.status && (r.status === 301 || r.status === 302)).length
        };
        
        res.json({
            url,
            stats,
            results: results.filter(r => !r.status || r.status >= 400),
            limited: links.length > 50,
            message: links.length > 50 ? 'Showing first 50 links. Sign up for full scan.' : null
        });
    } catch (error) {
        console.error('Public scan error:', error);
        res.status(500).json({ error: 'Scan failed' });
    }
});

// Helper functions
const cheerio = require('cheerio');
const axios = require('axios');

async function checkLink(url) {
    try {
        const response = await axios.head(url, {
            timeout: 5000,
            validateStatus: () => true,
            maxRedirects: 5
        });
        return {
            url,
            status: response.status,
            error: null
        };
    } catch (error) {
        return {
            url,
            status: null,
            error: error.message
        };
    }
}

async function extractLinks(url) {
    try {
        const response = await axios.get(url, { timeout: 10000 });
        const $ = cheerio.load(response.data);
        const links = new Set();
        
        $('a[href]').each((i, elem) => {
            let href = $(elem).attr('href');
            
            if (href.startsWith('/')) {
                const baseUrl = new URL(url);
                href = `${baseUrl.protocol}//${baseUrl.host}${href}`;
            } else if (!href.startsWith('http')) {
                return;
            }
            
            links.add(href);
        });
        
        return Array.from(links);
    } catch (error) {
        throw new Error(`Failed to extract links: ${error.message}`);
    }
}

// Queue processor
linkQueue.process(async (job) => {
    const { scanId, url, userId } = job.data;
    
    try {
        await pool.query('UPDATE scans SET status = $1 WHERE id = $2', ['processing', scanId]);
        
        const links = await extractLinks(url);
        
        const results = [];
        for (const link of links) {
            const result = await checkLink(link);
            results.push({
                ...result,
                foundOn: url
            });
            
            await pool.query(
                'INSERT INTO scan_results (scan_id, url, status_code, found_on, error_message) VALUES ($1, $2, $3, $4, $5)',
                [scanId, result.url, result.status, url, result.error]
            );
        }
        
        const brokenCount = results.filter(r => !r.status || r.status >= 400).length;
        
        await pool.query(
            'UPDATE scans SET status = $1, total_links = $2, broken_links = $3 WHERE id = $4',
            ['completed', links.length, brokenCount, scanId]
        );
        
        return results;
    } catch (error) {
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
                plan_limit INTEGER DEFAULT 100,
                scans_this_month INTEGER DEFAULT 0,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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