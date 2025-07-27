// dashboard-routes.js - User dashboard API endpoints
const express = require('express');
const router = express.Router();

// Middleware to verify authentication
const authenticateUser = async (req, res, next) => {
   const token = req.headers.authorization?.split(' ')[1];
   
   if (!token) {
       return res.status(401).json({ error: 'No token provided' });
   }
   
   const authResult = await req.authService.verifyToken(token);
   
   if (!authResult.success) {
       return res.status(401).json({ error: authResult.error });
   }
   
   req.user = authResult.user;
   req.userId = authResult.user.id;
   next();
};

// Get dashboard statistics
router.get('/scans/stats', authenticateUser, async (req, res) => {
 try {
   const userId = req.userId;
   const currentMonth = new Date();
   currentMonth.setDate(1);
   currentMonth.setHours(0, 0, 0, 0);
   
   // Total scans for user
   const totalScansResult = await req.pool.query(
     'SELECT COUNT(*) as count FROM scans WHERE user_id = $1',
     [userId]
   );
   
   // Monthly scans for user
   const monthlyScansResult = await req.pool.query(
     'SELECT COUNT(*) as count FROM scans WHERE user_id = $1 AND created_at >= $2',
     [userId, currentMonth]
   );
   
   // Total broken links found
   const totalBrokenLinksResult = await req.pool.query(`
     SELECT SUM(s.broken_links) as total 
     FROM scans s 
     WHERE s.user_id = $1 AND s.status = 'completed' AND s.broken_links IS NOT NULL
   `, [userId]);
   
   // Monthly broken links found
   const monthlyBrokenLinksResult = await req.pool.query(`
     SELECT SUM(s.broken_links) as total 
     FROM scans s 
     WHERE s.user_id = $1 AND s.status = 'completed' AND s.created_at >= $2 AND s.broken_links IS NOT NULL
   `, [userId, currentMonth]);
   
   res.json({
     totalScans: parseInt(totalScansResult.rows[0].count) || 0,
     monthlyScans: parseInt(monthlyScansResult.rows[0].count) || 0,
     totalBrokenLinks: parseInt(totalBrokenLinksResult.rows[0].total) || 0,
     monthlyBrokenLinks: parseInt(monthlyBrokenLinksResult.rows[0].total) || 0
   });
 } catch (error) {
   console.error('Error fetching dashboard stats:', error);
   res.status(500).json({ error: 'Internal server error' });
 }
});

// User profile endpoint
router.get('/auth/me', authenticateUser, async (req, res) => {
 try {
   const result = await req.pool.query(
     'SELECT id, email, name, created_at FROM users WHERE id = $1',
     [req.userId]
   );
   
   if (result.rows.length === 0) {
     return res.status(404).json({ error: 'User not found' });
   }
   
   res.json(result.rows[0]);
 } catch (error) {
   console.error('Error fetching user profile:', error);
   res.status(500).json({ error: 'Internal server error' });
 }
});

// Get user dashboard data
router.get('/dashboard', authenticateUser, async (req, res) => {
   try {
       const userId = req.user.id;
       
       // Get user stats
       const statsResult = await req.pool.query(`
           SELECT 
               COUNT(*) as total_scans,
               COUNT(CASE WHEN created_at > CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as scans_this_month,
               COUNT(CASE WHEN created_at > CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as scans_this_week,
               SUM(broken_links) as total_broken_links_found,
               AVG(scan_duration) as avg_scan_duration
           FROM scans 
           WHERE user_id = $1 AND status = 'completed'
       `, [userId]);
       
       // Get recent scans
       const recentScansResult = await req.pool.query(`
           SELECT 
               id, url, status, total_links, broken_links, 
               created_at, completed_at, scan_duration
           FROM scans 
           WHERE user_id = $1 
           ORDER BY created_at DESC 
           LIMIT 10
       `, [userId]);
       
       // Get most broken links by domain
       const topIssuesResult = await req.pool.query(`
           SELECT 
               SUBSTRING(url FROM '(?:.*://)?(?:www\.)?([^/?]+)') as domain,
               COUNT(*) as broken_count
           FROM scan_results sr
           JOIN scans s ON sr.scan_id = s.id
           WHERE s.user_id = $1 
               AND sr.status_code >= 400
               AND s.created_at > CURRENT_DATE - INTERVAL '30 days'
           GROUP BY domain
           ORDER BY broken_count DESC
           LIMIT 5
       `, [userId]);
       
       const stats = statsResult.rows[0];
       const recentScans = recentScansResult.rows;
       const topIssues = topIssuesResult.rows;
       
       res.json({
           user: {
               ...req.user,
               scansRemaining: req.user.planLimit - req.user.scansThisMonth
           },
           stats: {
               totalScans: parseInt(stats.total_scans) || 0,
               scansThisMonth: parseInt(stats.scans_this_month) || 0,
               scansThisWeek: parseInt(stats.scans_this_week) || 0,
               totalBrokenLinksFound: parseInt(stats.total_broken_links_found) || 0,
               avgScanDuration: Math.round(stats.avg_scan_duration) || 0
           },
           recentScans,
           topIssues
       });
   } catch (error) {
       console.error('Dashboard error:', error);
       res.status(500).json({ error: 'Failed to load dashboard data' });
   }
});

// Get detailed scan history with pagination
router.get('/scans/history', authenticateUser, async (req, res) => {
   try {
       const userId = req.user.id;
       const page = parseInt(req.query.page) || 1;
       const limit = parseInt(req.query.limit) || 20;
       const offset = (page - 1) * limit;
       
       // Get total count
       const countResult = await req.pool.query(
           'SELECT COUNT(*) FROM scans WHERE user_id = $1',
           [userId]
       );
       const totalCount = parseInt(countResult.rows[0].count);
       
       // Get scans
       const scansResult = await req.pool.query(`
           SELECT 
               id, url, status, total_links, broken_links,
               created_at, completed_at, scan_duration
           FROM scans 
           WHERE user_id = $1 
           ORDER BY created_at DESC 
           LIMIT $2 OFFSET $3
       `, [userId, limit, offset]);
       
       res.json({
           scans: scansResult.rows,
           pagination: {
               page,
               limit,
               total: totalCount,
               pages: Math.ceil(totalCount / limit)
           }
       });
   } catch (error) {
       console.error('Scan history error:', error);
       res.status(500).json({ error: 'Failed to load scan history' });
   }
});

// Get scan details
router.get('/scans/:id/details', authenticateUser, async (req, res) => {
   try {
       const userId = req.user.id;
       const scanId = req.params.id;
       
       // Get scan
       const scanResult = await req.pool.query(
           'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
           [scanId, userId]
       );
       
       if (scanResult.rows.length === 0) {
           return res.status(404).json({ error: 'Scan not found' });
       }
       
       const scan = scanResult.rows[0];
       
       // Get broken links
       const brokenLinksResult = await req.pool.query(`
           SELECT 
               url, status_code, found_on, error_message, response_time
           FROM scan_results 
           WHERE scan_id = $1 AND (status_code >= 400 OR status_code IS NULL)
           ORDER BY status_code DESC, url
       `, [scanId]);
       
       // Get status distribution
       const statusDistResult = await req.pool.query(`
           SELECT 
               CASE 
                   WHEN status_code >= 200 AND status_code < 300 THEN '2xx (OK)'
                   WHEN status_code >= 300 AND status_code < 400 THEN '3xx (Redirect)'
                   WHEN status_code >= 400 AND status_code < 500 THEN '4xx (Client Error)'
                   WHEN status_code >= 500 THEN '5xx (Server Error)'
                   ELSE 'No Response'
               END as status_group,
               COUNT(*) as count
           FROM scan_results
           WHERE scan_id = $1
           GROUP BY status_group
           ORDER BY status_group
       `, [scanId]);
       
       res.json({
           scan,
           brokenLinks: brokenLinksResult.rows,
           statusDistribution: statusDistResult.rows
       });
   } catch (error) {
       console.error('Scan details error:', error);
       res.status(500).json({ error: 'Failed to load scan details' });
   }
});

// Delete scan
router.delete('/scans/:id', authenticateUser, async (req, res) => {
   try {
       const userId = req.user.id;
       const scanId = req.params.id;
       
       const result = await req.pool.query(
           'DELETE FROM scans WHERE id = $1 AND user_id = $2 RETURNING id',
           [scanId, userId]
       );
       
       if (result.rows.length === 0) {
           return res.status(404).json({ error: 'Scan not found' });
       }
       
       res.json({ success: true, message: 'Scan deleted successfully' });
   } catch (error) {
       console.error('Delete scan error:', error);
       res.status(500).json({ error: 'Failed to delete scan' });
   }
});

// Get user profile
router.get('/profile', authenticateUser, async (req, res) => {
   try {
       const userId = req.user.id;
       
       const result = await req.pool.query(`
           SELECT 
               id, name, email, plan, plan_limit, scans_this_month,
               created_at, email_verified
           FROM users 
           WHERE id = $1
       `, [userId]);
       
       if (result.rows.length === 0) {
           return res.status(404).json({ error: 'User not found' });
       }
       
       res.json(result.rows[0]);
   } catch (error) {
       console.error('Profile error:', error);
       res.status(500).json({ error: 'Failed to load profile' });
   }
});

// Update user profile
router.put('/profile', authenticateUser, async (req, res) => {
   try {
       const userId = req.user.id;
       const { name, email } = req.body;
       
       // Check if email is already taken
       if (email && email !== req.user.email) {
           const emailCheck = await req.pool.query(
               'SELECT id FROM users WHERE email = $1 AND id != $2',
               [email, userId]
           );
           
           if (emailCheck.rows.length > 0) {
               return res.status(400).json({ error: 'Email already in use' });
           }
       }
       
       const result = await req.pool.query(`
           UPDATE users 
           SET name = COALESCE($1, name), 
               email = COALESCE($2, email),
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $3
           RETURNING id, name, email, plan
       `, [name, email, userId]);
       
       res.json({
           success: true,
           user: result.rows[0]
       });
   } catch (error) {
       console.error('Update profile error:', error);
       res.status(500).json({ error: 'Failed to update profile' });
   }
});

// Export scan results
router.get('/scans/:id/export', authenticateUser, async (req, res) => {
   try {
       const userId = req.user.id;
       const scanId = req.params.id;
       const format = req.query.format || 'csv';
       
       // Verify ownership
       const scanCheck = await req.pool.query(
           'SELECT url, created_at FROM scans WHERE id = $1 AND user_id = $2',
           [scanId, userId]
       );
       
       if (scanCheck.rows.length === 0) {
           return res.status(404).json({ error: 'Scan not found' });
       }
       
       const scan = scanCheck.rows[0];
       
       // Get all results
       const results = await req.pool.query(`
           SELECT 
               url, status_code, status, found_on, error_message, response_time
           FROM scan_results 
           WHERE scan_id = $1
           ORDER BY status_code DESC, url
       `, [scanId]);
       
       if (format === 'csv') {
           let csv = 'URL,Status Code,Status,Found On,Error,Response Time (ms)\n';
           results.rows.forEach(row => {
               csv += `"${row.url}",${row.status_code || ''},${row.status || ''},"${row.found_on}","${row.error_message || ''}",${row.response_time || ''}\n`;
           });
           
           res.setHeader('Content-Type', 'text/csv');
           res.setHeader('Content-Disposition', `attachment; filename="scan-${scanId}-${new Date().toISOString().split('T')[0]}.csv"`);
           res.send(csv);
       } else {
           res.status(400).json({ error: 'Unsupported format' });
       }
   } catch (error) {
       console.error('Export error:', error);
       res.status(500).json({ error: 'Failed to export scan results' });
   }
});

module.exports = router;