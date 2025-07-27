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
       req.userId = authResult.user.id;
       next();
   };

   // Enhanced GET /scans route with pagination and filters
   router.get('/', authenticateUser, async (req, res) => {
       try {
           const userId = req.userId;
           const page = parseInt(req.query.page) || 1;
           const limit = parseInt(req.query.limit) || 15;
           const offset = (page - 1) * limit;
           
           // Build WHERE clause based on filters
           let whereConditions = ['user_id = $1'];
           let params = [userId];
           let paramCount = 1;
           
           if (req.query.status) {
               paramCount++;
               whereConditions.push(`status = $${paramCount}`);
               params.push(req.query.status);
           }
           
           if (req.query.dateFrom) {
               paramCount++;
               whereConditions.push(`created_at >= $${paramCount}`);
               params.push(req.query.dateFrom);
           }
           
           if (req.query.dateTo) {
               paramCount++;
               whereConditions.push(`created_at <= $${paramCount}::date + interval '1 day'`);
               params.push(req.query.dateTo);
           }
           
           const whereClause = whereConditions.join(' AND ');
           
           // Get total count for pagination
           const countResult = await pool.query(
               `SELECT COUNT(*) as count FROM scans WHERE ${whereClause}`,
               params
           );
           
           const totalCount = parseInt(countResult.rows[0].count);
           const totalPages = Math.ceil(totalCount / limit);
           
           // Get scans with pagination
           const scansResult = await pool.query(`
               SELECT 
                   id, 
                   url, 
                   status, 
                   total_links, 
                   broken_links, 
                   created_at, 
                   completed_at
               FROM scans 
               WHERE ${whereClause}
               ORDER BY created_at DESC 
               LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
           `, [...params, limit, offset]);
           
           res.json({
               scans: scansResult.rows,
               pagination: {
                   currentPage: page,
                   totalPages: totalPages,
                   totalCount: totalCount,
                   hasMore: page < totalPages
               }
           });
       } catch (error) {
           console.error('Error fetching scans:', error);
           res.status(500).json({ error: 'Internal server error' });
       }
   });

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

   // Export scan results as CSV
   router.get('/:id/export/csv', authenticateUser, async (req, res) => {
       try {
           const scanId = req.params.id;
           const userId = req.userId;
           
           // Verify scan belongs to user
           const scanCheck = await pool.query(
               'SELECT url, created_at FROM scans WHERE id = $1 AND user_id = $2',
               [scanId, userId]
           );
           
           if (scanCheck.rows.length === 0) {
               return res.status(404).json({ error: 'Scan not found' });
           }
           
           const scan = scanCheck.rows[0];
           
           // Get all scan results
           const resultsQuery = await pool.query(`
               SELECT 
                   url, 
                   status_code, 
                   found_on, 
                   error_message
               FROM scan_results 
               WHERE scan_id = $1
               ORDER BY status_code DESC, url
           `, [scanId]);
           
           // Generate CSV content
           const csvHeader = 'URL,Status Code,Found On,Error Message\n';
           const csvRows = resultsQuery.rows.map(row => 
               `"${row.url}","${row.status_code}","${row.found_on}","${row.error_message || ''}"`
           ).join('\n');
           
           const csvContent = csvHeader + csvRows;
           
           // Set headers for file download
           const filename = `checkmylinks-${scan.url.replace(/[^a-zA-Z0-9]/g, '-')}-${new Date().toISOString().split('T')[0]}.csv`;
           res.setHeader('Content-Type', 'text/csv');
           res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
           
           res.send(csvContent);
       } catch (error) {
           console.error('Error exporting CSV:', error);
           res.status(500).json({ error: 'Internal server error' });
       }
   });

   // Enhanced GET /scans/:id route with scan results
   router.get('/:id', authenticateUser, async (req, res) => {
       try {
           const scanId = req.params.id;
           const userId = req.userId;
           
           // Get scan details
           const scanResult = await pool.query(`
               SELECT 
                   id, 
                   url, 
                   status, 
                   total_links, 
                   broken_links, 
                   created_at, 
                   completed_at
               FROM scans 
               WHERE id = $1 AND user_id = $2
           `, [scanId, userId]);
           
           if (scanResult.rows.length === 0) {
               return res.status(404).json({ error: 'Scan not found' });
           }
           
           const scan = scanResult.rows[0];
           
           // Get scan results (broken links only for performance, or all if requested)
           const showAll = req.query.all === 'true';
           const resultsQuery = await pool.query(`
               SELECT 
                   url, 
                   status_code, 
                   found_on, 
                   error_message
               FROM scan_results 
               WHERE scan_id = $1 ${showAll ? '' : 'AND status_code != 200'}
               ORDER BY status_code DESC, url
           `, [scanId]);
           
           scan.scan_results = resultsQuery.rows;
           
           res.json(scan);
       } catch (error) {
           console.error('Error fetching scan details:', error);
           res.status(500).json({ error: 'Internal server error' });
       }
   });

   return router;
};