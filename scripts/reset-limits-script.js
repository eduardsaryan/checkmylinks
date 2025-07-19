#!/usr/bin/env node
// scripts/reset-monthly-limits.js
// Run this as a cron job on the 1st of each month

require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

async function resetMonthlyLimits() {
    try {
        console.log('Starting monthly limit reset...');
        
        const result = await pool.query(
            'UPDATE users SET scans_this_month = 0 RETURNING id, email'
        );
        
        console.log(`Reset scan counts for ${result.rowCount} users`);
        
        await pool.end();
        process.exit(0);
    } catch (error) {
        console.error('Error resetting monthly limits:', error);
        await pool.end();
        process.exit(1);
    }
}

resetMonthlyLimits();