// routes/scans.js - Scan endpoints
const express = require('express');
const router = express.Router();

// Export a function that accepts dependencies
module.exports = (pool, queue, authService, emailService) => {
    // Middleware to verify authentication
    const authenticateUser = async (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }
        
        const authResult = await authService.verifyToken(token);
        
        if (!authResult.success) {
            return res.status(401).json({ error: authResult.error });
        }
        
        req.user = authResult.user;
        next();
    };

    // Create new scan
    router.post('/', authenticateUser, async (req, res) => {
        const { url } = req.body;
        const userId = req.user.id;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }
        
        // Validate URL
        try {
            new URL(url);
        } catch (error) {
            return res.status(400).json({ error: 'Invalid URL' });
        }
        
        // Check scan limit
        if (req.user.scansThisMonth >= req.user.planLimit) {
            return res.status(403).json({ 
                error: 'Monthly scan limit reached. Please upgrade your plan.' 
            });
        }
        
        try {
            // Create scan record
            const scanResult = await pool.query(
                `INSERT INTO scans (user_id, url, status) 
                 VALUES ($1, $2, 'pending') 
                 RETURNING id, url, status, created_at`,
                [userId, url]
            );
            
            const scan = scanResult.rows[0];
            
            // Update user's scan count
            await pool.query(
                'UPDATE users SET scans_this_month = scans_this_month + 1 WHERE id = $1',
                [userId]
            );
            
            // Add to queue
            await queue.add('scan-website', {
                scanId: scan.id,
                url: url,
                userId: userId
            });
            
            res.json(scan);
        } catch (error) {
            console.error('Scan creation error:', error);
            res.status(500).json({ error: 'Failed to create scan' });
        }
    });

    // Get scan by ID
    router.get('/:id', authenticateUser, async (req, res) => {
        const scanId = req.params.id;
        const userId = req.user.id;
        
        try {
            const result = await pool.query(
                'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
                [scanId, userId]
            );
            
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Scan not found' });
            }
            
            const scan = result.rows[0];
            
            // If completed, include some results
            if (scan.status === 'completed') {
                const resultsQuery = await pool.query(
                    `SELECT url, status_code, found_on 
                     FROM scan_results 
                     WHERE scan_id = $1 AND (status_code >= 400 OR status_code IS NULL)
                     LIMIT 50`,
                    [scanId]
                );
                
                scan.results = resultsQuery.rows;
            }
            
            res.json(scan);
        } catch (error) {
            console.error('Get scan error:', error);
            res.status(500).json({ error: 'Failed to retrieve scan' });
        }
    });

    // Get user's scans
    router.get('/', authenticateUser, async (req, res) => {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 10;
        const offset = parseInt(req.query.offset) || 0;
        
        try {
            const result = await pool.query(
                `SELECT * FROM scans 
                 WHERE user_id = $1 
                 ORDER BY created_at DESC 
                 LIMIT $2 OFFSET $3`,
                [userId, limit, offset]
            );
            
            const countResult = await pool.query(
                'SELECT COUNT(*) FROM scans WHERE user_id = $1',
                [userId]
            );
            
            res.json({
                scans: result.rows,
                total: parseInt(countResult.rows[0].count),
                limit,
                offset
            });
        } catch (error) {
            console.error('Get scans error:', error);
            res.status(500).json({ error: 'Failed to retrieve scans' });
        }
    });

    return router;
};