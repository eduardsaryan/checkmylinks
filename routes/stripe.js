// stripe-integration.js
// Complete Stripe payment integration for Dead Link Checker SaaS

const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.sendStatus(401);
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Webhook middleware for Stripe
const webhookMiddleware = express.raw({ type: 'application/json' });

// Routes

// 1. Create Checkout Session
app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const { priceId, planType } = req.body;
    const userId = req.user.id;
    
    // Get user details
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Define price IDs (create these in Stripe Dashboard)
    const priceIds = {
      basic: process.env.STRIPE_BASIC_PRICE_ID, // $19/month
      pro: process.env.STRIPE_PRO_PRICE_ID,     // $39/month
    };

    const session = await stripe.checkout.sessions.create({
      customer_email: user.email,
      billing_address_collection: 'required',
      line_items: [
        {
          price: priceIds[planType],
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL}/dashboard?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/pricing`,
      metadata: {
        userId: userId.toString(),
        planType: planType,
      },
      subscription_data: {
        trial_period_days: 14,
        metadata: {
          userId: userId.toString(),
          planType: planType,
        },
      },
    });

    res.json({ sessionId: session.id });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// 2. Handle successful checkout
app.get('/api/checkout-success', authenticateToken, async (req, res) => {
  try {
    const { session_id } = req.query;
    const session = await stripe.checkout.sessions.retrieve(session_id);
    
    if (session.payment_status === 'paid') {
      const userId = session.metadata.userId;
      const planType = session.metadata.planType;
      
      // Update user subscription in database
      await pool.query(`
        UPDATE users 
        SET 
          stripe_customer_id = $1,
          subscription_status = 'trialing',
          plan_type = $2,
          updated_at = NOW()
        WHERE id = $3
      `, [session.customer, planType, userId]);
      
      // Create subscription record
      await pool.query(`
        INSERT INTO subscriptions (user_id, stripe_subscription_id, plan_type, status, trial_end)
        VALUES ($1, $2, $3, 'trialing', NOW() + INTERVAL '14 days')
      `, [userId, session.subscription, planType]);
      
      res.json({ success: true, message: 'Subscription created successfully' });
    } else {
      res.status(400).json({ error: 'Payment not completed' });
    }
  } catch (error) {
    console.error('Error handling checkout success:', error);
    res.status(500).json({ error: 'Failed to process checkout success' });
  }
});

// 3. Customer Portal for managing subscriptions
app.post('/api/create-portal-session', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get user's Stripe customer ID
    const userResult = await pool.query('SELECT stripe_customer_id FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];
    
    if (!user.stripe_customer_id) {
      return res.status(400).json({ error: 'No subscription found' });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: `${process.env.FRONTEND_URL}/dashboard`,
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Error creating portal session:', error);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// 4. Get subscription status
app.get('/api/subscription-status', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const result = await pool.query(`
      SELECT s.*, u.plan_type, u.subscription_status
      FROM subscriptions s
      JOIN users u ON s.user_id = u.id
      WHERE s.user_id = $1
      ORDER BY s.created_at DESC
      LIMIT 1
    `, [userId]);
    
    if (result.rows.length === 0) {
      return res.json({ hasSubscription: false });
    }
    
    const subscription = result.rows[0];
    
    // Check if trial has expired
    const now = new Date();
    const trialEnd = new Date(subscription.trial_end);
    const isTrialExpired = now > trialEnd;
    
    res.json({
      hasSubscription: true,
      planType: subscription.plan_type,
      status: subscription.status,
      trialEnd: subscription.trial_end,
      isTrialExpired: isTrialExpired,
      isActive: subscription.status === 'active' || (subscription.status === 'trialing' && !isTrialExpired),
    });
  } catch (error) {
    console.error('Error getting subscription status:', error);
    res.status(500).json({ error: 'Failed to get subscription status' });
  }
});

// 5. Stripe Webhooks Handler
app.post('/api/stripe-webhooks', webhookMiddleware, async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'customer.subscription.created':
        await handleSubscriptionCreated(event.data.object);
        break;
        
      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(event.data.object);
        break;
        
      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(event.data.object);
        break;
        
      case 'invoice.payment_succeeded':
        await handlePaymentSucceeded(event.data.object);
        break;
        
      case 'invoice.payment_failed':
        await handlePaymentFailed(event.data.object);
        break;
        
      case 'customer.subscription.trial_will_end':
        await handleTrialWillEnd(event.data.object);
        break;
        
      default:
        console.log(`Unhandled event type: ${event.type}`);
    }
    
    res.json({ received: true });
  } catch (error) {
    console.error('Error processing webhook:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Webhook handlers
async function handleSubscriptionCreated(subscription) {
  const userId = subscription.metadata.userId;
  
  await pool.query(`
    UPDATE subscriptions 
    SET stripe_subscription_id = $1, status = $2, updated_at = NOW()
    WHERE user_id = $3
  `, [subscription.id, subscription.status, userId]);
  
  await pool.query(`
    UPDATE users 
    SET subscription_status = $1, updated_at = NOW()
    WHERE id = $2
  `, [subscription.status, userId]);
}

async function handleSubscriptionUpdated(subscription) {
  const userId = subscription.metadata.userId;
  
  await pool.query(`
    UPDATE subscriptions 
    SET status = $1, updated_at = NOW()
    WHERE stripe_subscription_id = $2
  `, [subscription.status, subscription.id]);
  
  await pool.query(`
    UPDATE users 
    SET subscription_status = $1, updated_at = NOW()
    WHERE id = $2
  `, [subscription.status, userId]);
}

async function handleSubscriptionDeleted(subscription) {
  const userId = subscription.metadata.userId;
  
  await pool.query(`
    UPDATE subscriptions 
    SET status = 'canceled', updated_at = NOW()
    WHERE stripe_subscription_id = $1
  `, [subscription.id]);
  
  await pool.query(`
    UPDATE users 
    SET subscription_status = 'canceled', updated_at = NOW()
    WHERE id = $1
  `, [userId]);
  
  // Send cancellation email
  await sendCancellationEmail(userId);
}

async function handlePaymentSucceeded(invoice) {
  if (invoice.subscription) {
    const subscription = await stripe.subscriptions.retrieve(invoice.subscription);
    const userId = subscription.metadata.userId;
    
    // Update payment history
    await pool.query(`
      INSERT INTO payment_history (user_id, stripe_invoice_id, amount, status, paid_at)
      VALUES ($1, $2, $3, 'paid', NOW())
    `, [userId, invoice.id, invoice.amount_paid]);
    
    // Send payment success email
    await sendPaymentSuccessEmail(userId, invoice.amount_paid / 100);
  }
}

async function handlePaymentFailed(invoice) {
  if (invoice.subscription) {
    const subscription = await stripe.subscriptions.retrieve(invoice.subscription);
    const userId = subscription.metadata.userId;
    
    // Update payment history
    await pool.query(`
      INSERT INTO payment_history (user_id, stripe_invoice_id, amount, status, failed_at)
      VALUES ($1, $2, $3, 'failed', NOW())
    `, [userId, invoice.id, invoice.amount_due]);
    
    // Send payment failed email
    await sendPaymentFailedEmail(userId);
  }
}

async function handleTrialWillEnd(subscription) {
  const userId = subscription.metadata.userId;
  await sendTrialEndingEmail(userId);
}

// Email functions (integrate with your email service)
async function sendPaymentSuccessEmail(userId, amount) {
  const userResult = await pool.query('SELECT email, first_name FROM users WHERE id = $1', [userId]);
  const user = userResult.rows[0];
  
  // Implement email sending logic here
  console.log(`Sending payment success email to ${user.email} for ${amount}`);
}

async function sendPaymentFailedEmail(userId) {
  const userResult = await pool.query('SELECT email, first_name FROM users WHERE id = $1', [userId]);
  const user = userResult.rows[0];
  
  // Implement email sending logic here
  console.log(`Sending payment failed email to ${user.email}`);
}

async function sendTrialEndingEmail(userId) {
  const userResult = await pool.query('SELECT email, first_name FROM users WHERE id = $1', [userId]);
  const user = userResult.rows[0];
  
  // Implement email sending logic here
  console.log(`Sending trial ending email to ${user.email}`);
}

async function sendCancellationEmail(userId) {
  const userResult = await pool.query('SELECT email, first_name FROM users WHERE id = $1', [userId]);
  const user = userResult.rows[0];
  
  // Implement email sending logic here
  console.log(`Sending cancellation email to ${user.email}`);
}

// Frontend integration functions
const frontendIntegration = `
// Frontend Stripe integration (React component)
import React, { useState } from 'react';
import { loadStripe } from '@stripe/stripe-js';

const stripePromise = loadStripe(process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY);

const CheckoutButton = ({ planType, planName, price }) => {
  const [loading, setLoading] = useState(false);

  const handleCheckout = async () => {
    setLoading(true);
    
    try {
      const response = await fetch('/api/create-checkout-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + localStorage.getItem('token'),
        },
        body: JSON.stringify({ planType }),
      });
      
      const { sessionId } = await response.json();
      
      const stripe = await stripePromise;
      const { error } = await stripe.redirectToCheckout({ sessionId });
      
      if (error) {
        console.error('Stripe error:', error);
        alert('Payment failed. Please try again.');
      }
    } catch (error) {
      console.error('Checkout error:', error);
      alert('Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleCheckout}
      disabled={loading}
      className="btn btn-primary"
      style={{ width: '100%' }}
    >
      {loading ? 'Processing...' : 'Start Free Trial'}
    </button>
  );
};

// Usage in pricing component
const PricingCard = ({ plan }) => (
  <div className="pricing-card">
    <div className="plan-name">{plan.name}</div>
    <div className="plan-price">{plan.price}<span>/month</span></div>
    <div className="plan-description">{plan.description}</div>
    
    <ul className="plan-features">
      {plan.features.map((feature, index) => (
        <li key={index}>{feature}</li>
      ))}
    </ul>
    
    <CheckoutButton
      planType={plan.type}
      planName={plan.name}
      price={plan.price}
    />
  </div>
);

export { CheckoutButton, PricingCard };
`;

// Database schema
const databaseSchema = `
-- Database schema for subscription management

-- Users table (add these columns to your existing users table)
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'inactive';
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_type VARCHAR(50);

-- Subscriptions table
CREATE TABLE IF NOT EXISTS subscriptions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  stripe_subscription_id VARCHAR(255) UNIQUE,
  plan_type VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL,
  trial_end TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Payment history table
CREATE TABLE IF NOT EXISTS payment_history (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  stripe_invoice_id VARCHAR(255),
  amount INTEGER NOT NULL, -- in cents
  status VARCHAR(50) NOT NULL,
  paid_at TIMESTAMP,
  failed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_payment_history_user_id ON payment_history(user_id);
`;

module.exports = {
  // Export functions for use in your main app
  authenticateToken,
  webhookMiddleware,
  frontendIntegration,
  databaseSchema,
};

// Environment variables you need to set:
/*
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_BASIC_PRICE_ID=price_...
STRIPE_PRO_PRICE_ID=price_...
FRONTEND_URL=http://localhost:3000
DATABASE_URL=postgresql://...
JWT_SECRET=your_jwt_secret
*/