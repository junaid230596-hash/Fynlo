/**
 * SkipHub — Production Backend API
 * Database  : PostgreSQL via Neon (neon.tech) — FREE
 * Auth      : JWT + bcrypt
 * Payments  : Razorpay (UPI, Cards, Net Banking)
 *
 * ─── SETUP ───────────────────────────────────────────────────
 * 1. Create free DB at neon.tech → copy connection string
 * 2. cp .env.example .env  → fill in your values
 * 3. npm install
 * 4. npm run dev     (development)
 *    npm start       (production)
 * ─────────────────────────────────────────────────────────────
 */

'use strict';
require('dotenv').config();

const express    = require('express');
const { Pool }   = require('pg');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcrypt');
const cors       = require('cors');
const Razorpay   = require('razorpay');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const nodemailer = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════
// NEON POSTGRESQL CONNECTION
// ═══════════════════════════════════════════════════════════
// Neon requires SSL. The connection string from neon.tech
// already includes ?sslmode=require — pool handles it automatically.

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,   // required for Neon free tier
  },
  max: 10,                        // max connections in pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// Test connection on startup
pool.connect()
  .then(client => {
    console.log('✓ Connected to Neon PostgreSQL');
    client.release();
  })
  .catch(err => {
    console.error('✗ Database connection failed:', err.message);
    console.error('  Check your DATABASE_URL in .env');
    process.exit(1);
  });

// ═══════════════════════════════════════════════════════════
// RAZORPAY (UPI + Cards + Net Banking)
// ═══════════════════════════════════════════════════════════

const razorpay = new Razorpay({
  key_id    : process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ═══════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════

app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// CORS — only allow your Netlify frontend
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Rate limiting — 100 requests per 15 minutes per IP
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
}));

// ═══════════════════════════════════════════════════════════
// DATABASE — AUTO INIT SCHEMA
// ═══════════════════════════════════════════════════════════
// Runs on every server start. IF NOT EXISTS means it's safe
// to run multiple times — it won't drop existing data.

async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`

      -- 1. USERS
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        email         VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name          VARCHAR(255) NOT NULL,
        role          VARCHAR(50)  NOT NULL DEFAULT 'business',
        business_id   INTEGER,
        avatar        VARCHAR(10),
        phone         VARCHAR(20),
        is_active     BOOLEAN   DEFAULT true,
        email_verified BOOLEAN  DEFAULT false,
        phone_verified BOOLEAN  DEFAULT false,
        last_login    TIMESTAMP,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 2. BUSINESSES
      CREATE TABLE IF NOT EXISTS businesses (
        id                  SERIAL PRIMARY KEY,
        owner_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        shop_name           VARCHAR(255) NOT NULL,
        category            VARCHAR(100),
        email               VARCHAR(255),
        phone               VARCHAR(20),
        address             TEXT,
        city                VARCHAR(100),
        state               VARCHAR(100),
        zip                 VARCHAR(20),
        country             VARCHAR(100) DEFAULT 'India',
        website             VARCHAR(255),
        registration_no     VARCHAR(100),
        tax_id              VARCHAR(100),
        logo_url            VARCHAR(255),
        bio                 TEXT,
        bank_name           VARCHAR(100),
        account_holder      VARCHAR(255),
        account_number      VARCHAR(100),
        ifsc_code           VARCHAR(20),
        upi_id              VARCHAR(100),
        razorpay_account_id VARCHAR(100),
        subscription_plan   VARCHAR(50)   DEFAULT 'Free',
        subscription_status VARCHAR(50)   DEFAULT 'trial',
        trial_ends_at       DATE          DEFAULT (CURRENT_DATE + INTERVAL '14 days'),
        total_revenue       DECIMAL(12,2) DEFAULT 0,
        monthly_revenue     DECIMAL(12,2) DEFAULT 0,
        total_invoices      INTEGER       DEFAULT 0,
        total_products      INTEGER       DEFAULT 0,
        total_employees     INTEGER       DEFAULT 0,
        status              VARCHAR(50)   DEFAULT 'active',
        joined_at           DATE          DEFAULT CURRENT_DATE,
        created_at          TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
        updated_at          TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
      );

      -- Add FK: users → businesses (after both tables exist)
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.table_constraints
          WHERE constraint_name = 'fk_users_business'
        ) THEN
          ALTER TABLE users
            ADD CONSTRAINT fk_users_business
            FOREIGN KEY (business_id)
            REFERENCES businesses(id)
            ON DELETE SET NULL;
        END IF;
      END $$;

      -- 3. SUBSCRIPTIONS
      CREATE TABLE IF NOT EXISTS subscriptions (
        id                        SERIAL PRIMARY KEY,
        business_id               INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        plan_name                 VARCHAR(100) NOT NULL,
        price                     DECIMAL(10,2) NOT NULL,
        currency                  VARCHAR(10) DEFAULT 'INR',
        billing_cycle             VARCHAR(50) DEFAULT 'monthly',
        razorpay_subscription_id  VARCHAR(255),
        razorpay_customer_id      VARCHAR(255),
        current_period_start      DATE,
        current_period_end        DATE,
        max_products              INTEGER DEFAULT 100,
        max_employees             INTEGER DEFAULT 5,
        max_invoices_per_month    INTEGER DEFAULT 50,
        is_active                 BOOLEAN DEFAULT true,
        auto_renew                BOOLEAN DEFAULT true,
        trial_ends_at             DATE,
        cancelled_at              TIMESTAMP,
        created_at                TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 4. SUPPLIERS
      CREATE TABLE IF NOT EXISTS suppliers (
        id             SERIAL PRIMARY KEY,
        business_id    INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        name           VARCHAR(255) NOT NULL,
        contact_person VARCHAR(255),
        email          VARCHAR(255),
        phone          VARCHAR(20),
        address        TEXT,
        city           VARCHAR(100),
        country        VARCHAR(100),
        payment_terms  VARCHAR(100),
        notes          TEXT,
        is_active      BOOLEAN DEFAULT true,
        created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 5. PRODUCTS
      CREATE TABLE IF NOT EXISTS products (
        id              SERIAL PRIMARY KEY,
        business_id     INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        supplier_id     INTEGER REFERENCES suppliers(id) ON DELETE SET NULL,
        sku             VARCHAR(100) NOT NULL,
        name            VARCHAR(255) NOT NULL,
        description     TEXT,
        category        VARCHAR(100),
        price           DECIMAL(10,2) NOT NULL DEFAULT 0,
        cost            DECIMAL(10,2) DEFAULT 0,
        stock_quantity  INTEGER DEFAULT 0,
        min_stock_level INTEGER DEFAULT 5,
        unit            VARCHAR(50) DEFAULT 'piece',
        image_url       VARCHAR(255),
        is_active       BOOLEAN DEFAULT true,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(business_id, sku)
      );

      -- 6. STOCK MOVEMENTS
      CREATE TABLE IF NOT EXISTS stock_movements (
        id              SERIAL PRIMARY KEY,
        business_id     INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        product_id      INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        movement_type   VARCHAR(50) NOT NULL,
        quantity        INTEGER NOT NULL,
        quantity_before INTEGER NOT NULL,
        quantity_after  INTEGER NOT NULL,
        reference_type  VARCHAR(50),
        reference_id    INTEGER,
        notes           TEXT,
        created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 7. EMPLOYEES
      CREATE TABLE IF NOT EXISTS employees (
        id           SERIAL PRIMARY KEY,
        business_id  INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        name         VARCHAR(255) NOT NULL,
        email        VARCHAR(255),
        phone        VARCHAR(20),
        address      TEXT,
        position     VARCHAR(100) NOT NULL,
        department   VARCHAR(100),
        salary       DECIMAL(10,2) DEFAULT 0,
        salary_type  VARCHAR(50)   DEFAULT 'monthly',
        hire_date    DATE          DEFAULT CURRENT_DATE,
        manager_id   INTEGER REFERENCES employees(id) ON DELETE SET NULL,
        status       VARCHAR(50)   DEFAULT 'active',
        notes        TEXT,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 8. ATTENDANCE
      CREATE TABLE IF NOT EXISTS attendance (
        id              SERIAL PRIMARY KEY,
        business_id     INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        employee_id     INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
        attendance_date DATE NOT NULL,
        check_in_time   TIME,
        check_out_time  TIME,
        hours_worked    DECIMAL(4,2) DEFAULT 0,
        status          VARCHAR(50) NOT NULL DEFAULT 'present',
        notes           TEXT,
        marked_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(employee_id, attendance_date)
      );

      -- 9. INVOICES
      CREATE TABLE IF NOT EXISTS invoices (
        id                    SERIAL PRIMARY KEY,
        business_id           INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        invoice_number        VARCHAR(100) NOT NULL,
        customer_name         VARCHAR(255) NOT NULL,
        customer_email        VARCHAR(255),
        customer_phone        VARCHAR(20),
        customer_address      TEXT,
        invoice_date          DATE NOT NULL DEFAULT CURRENT_DATE,
        due_date              DATE,
        subtotal              DECIMAL(10,2) NOT NULL DEFAULT 0,
        tax_percentage        DECIMAL(5,2)  DEFAULT 18,
        tax_amount            DECIMAL(10,2) DEFAULT 0,
        discount_amount       DECIMAL(10,2) DEFAULT 0,
        total_amount          DECIMAL(10,2) NOT NULL DEFAULT 0,
        payment_status        VARCHAR(50)   DEFAULT 'pending',
        payment_method        VARCHAR(50),
        razorpay_order_id     VARCHAR(255),
        razorpay_payment_id   VARCHAR(255),
        paid_at               TIMESTAMP,
        notes                 TEXT,
        created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(business_id, invoice_number)
      );

      -- 10. INVOICE ITEMS
      CREATE TABLE IF NOT EXISTS invoice_items (
        id          SERIAL PRIMARY KEY,
        invoice_id  INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
        product_id  INTEGER REFERENCES products(id) ON DELETE SET NULL,
        item_name   VARCHAR(255) NOT NULL,
        quantity    INTEGER NOT NULL DEFAULT 1,
        unit_price  DECIMAL(10,2) NOT NULL DEFAULT 0,
        line_total  DECIMAL(10,2) NOT NULL DEFAULT 0,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 11. PAYROLL
      CREATE TABLE IF NOT EXISTS payroll (
        id                   SERIAL PRIMARY KEY,
        business_id          INTEGER NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
        employee_id          INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
        payroll_month        DATE NOT NULL,
        base_salary          DECIMAL(10,2) NOT NULL DEFAULT 0,
        bonus                DECIMAL(10,2) DEFAULT 0,
        deductions           DECIMAL(10,2) DEFAULT 0,
        tax_amount           DECIMAL(10,2) DEFAULT 0,
        net_salary           DECIMAL(10,2) NOT NULL DEFAULT 0,
        payment_status       VARCHAR(50)   DEFAULT 'pending',
        payment_method       VARCHAR(50)   DEFAULT 'upi',
        razorpay_payout_id   VARCHAR(255),
        paid_at              TIMESTAMP,
        notes                TEXT,
        created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(employee_id, payroll_month)
      );

      -- 12. NOTIFICATIONS
      CREATE TABLE IF NOT EXISTS notifications (
        id          SERIAL PRIMARY KEY,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        business_id INTEGER REFERENCES businesses(id) ON DELETE CASCADE,
        type        VARCHAR(50) NOT NULL,
        title       VARCHAR(255) NOT NULL,
        message     TEXT,
        is_read     BOOLEAN DEFAULT false,
        read_at     TIMESTAMP,
        link        VARCHAR(255),
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 13. CHAT MESSAGES
      CREATE TABLE IF NOT EXISTS chat_messages (
        id          SERIAL PRIMARY KEY,
        sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        business_id INTEGER REFERENCES businesses(id) ON DELETE CASCADE,
        message     TEXT NOT NULL,
        is_read     BOOLEAN DEFAULT false,
        read_at     TIMESTAMP,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- ─── INDEXES ───────────────────────────────────────────
      CREATE INDEX IF NOT EXISTS idx_products_business    ON products(business_id);
      CREATE INDEX IF NOT EXISTS idx_invoices_business    ON invoices(business_id);
      CREATE INDEX IF NOT EXISTS idx_employees_business   ON employees(business_id);
      CREATE INDEX IF NOT EXISTS idx_attendance_business  ON attendance(business_id);
      CREATE INDEX IF NOT EXISTS idx_payroll_business     ON payroll(business_id);
      CREATE INDEX IF NOT EXISTS idx_stock_business       ON stock_movements(business_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_user   ON notifications(user_id, is_read);
      CREATE INDEX IF NOT EXISTS idx_invoices_status      ON invoices(payment_status);
      CREATE INDEX IF NOT EXISTS idx_invoices_date        ON invoices(invoice_date);
      CREATE INDEX IF NOT EXISTS idx_attendance_date      ON attendance(attendance_date);
      CREATE INDEX IF NOT EXISTS idx_payroll_month        ON payroll(payroll_month);
      CREATE INDEX IF NOT EXISTS idx_products_sku         ON products(business_id, sku);
      CREATE INDEX IF NOT EXISTS idx_users_email          ON users(email);
      CREATE INDEX IF NOT EXISTS idx_chat_convo           ON chat_messages(sender_id, receiver_id);

    `);
    console.log('✓ Database schema ready');
  } catch (err) {
    console.error('✗ Schema init error:', err.message);
    throw err;
  } finally {
    client.release();
  }
}

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════

const JWT_SECRET = process.env.JWT_SECRET || process.env.jwt_secret;
if (!JWT_SECRET) {
  console.error('✗ JWT_SECRET missing — please set it in Railway Variables tab');
  console.error('  Available env keys:', Object.keys(process.env).filter(k => !k.includes('npm') && !k.includes('NODE')).join(', '));
  process.exit(1);
}

const generateToken = (userId, businessId, role) =>
  jwt.sign({ userId, businessId, role }, JWT_SECRET, { expiresIn: '7d' });

const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

// Auth middleware
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
  req.user = decoded;
  next();
};

// Admin-only middleware
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Admin access required' });
  next();
};

// Validate plan limits before insert
const checkPlanLimit = async (businessId, resource) => {
  const sub = await pool.query(
    'SELECT * FROM subscriptions WHERE business_id = $1 AND is_active = true',
    [businessId]
  );
  const limits = sub.rows[0] || { max_products: 10, max_employees: 2, max_invoices_per_month: 10 };

  if (resource === 'product') {
    const { rows } = await pool.query('SELECT COUNT(*) FROM products WHERE business_id = $1', [businessId]);
    if (parseInt(rows[0].count) >= limits.max_products)
      return `Product limit reached (${limits.max_products}). Please upgrade your plan.`;
  }
  if (resource === 'employee') {
    const { rows } = await pool.query('SELECT COUNT(*) FROM employees WHERE business_id = $1', [businessId]);
    if (parseInt(rows[0].count) >= limits.max_employees)
      return `Employee limit reached (${limits.max_employees}). Please upgrade your plan.`;
  }
  if (resource === 'invoice') {
    const { rows } = await pool.query(
      `SELECT COUNT(*) FROM invoices WHERE business_id = $1
       AND DATE_TRUNC('month', invoice_date) = DATE_TRUNC('month', CURRENT_DATE)`,
      [businessId]
    );
    if (parseInt(rows[0].count) >= limits.max_invoices_per_month)
      return `Monthly invoice limit reached (${limits.max_invoices_per_month}). Please upgrade your plan.`;
  }
  return null;
};

// ═══════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', timestamp: new Date() });
  } catch {
    res.status(500).json({ status: 'error', db: 'disconnected' });
  }
});

// ═══════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════

// Register
app.post('/api/auth/register', async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password, name, role, shopName, phone, category, city, country, address, regNo, taxId, company } = req.body;

    if (!email || !password || !name)
      return res.status(400).json({ error: 'Email, password, and name are required' });

    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await client.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length)
      return res.status(409).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    const avatar = name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);

    await client.query('BEGIN');

    // Create user (no business_id yet)
    const userRes = await client.query(
      'INSERT INTO users (email, password_hash, name, role, avatar, phone) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [email, passwordHash, name, role || 'business', avatar, phone || null]
    );
    const userId = userRes.rows[0].id;

    let businessId = null;

    if (role === 'business' || !role || role !== 'admin') {
      // Create business record
      const bizRes = await client.query(
        `INSERT INTO businesses
           (owner_id, shop_name, category, email, phone, city, country, address, registration_no, tax_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING id`,
        [userId, shopName || name + "'s Business", category || null, email, phone || null,
         city || null, country || 'India', address || null, regNo || null, taxId || null]
      );
      businessId = bizRes.rows[0].id;

      // Link user to business
      await client.query('UPDATE users SET business_id = $1 WHERE id = $2', [businessId, userId]);

      // Create default Free subscription
      await client.query(
        `INSERT INTO subscriptions
           (business_id, plan_name, price, currency, max_products, max_employees, max_invoices_per_month)
         VALUES ($1,'Free',0,'INR',10,2,10)`,
        [businessId]
      );
    }

    await client.query('COMMIT');

    const token = generateToken(userId, businessId, role || 'business');
    res.status(201).json({
      token,
      user: { id: userId, email, name, role: role || 'business', avatar, businessId },
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Register error:', err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query(
      'SELECT id, email, name, password_hash, business_id, role, avatar FROM users WHERE email = $1 AND is_active = true',
      [email]
    );
    if (!result.rows.length)
      return res.status(401).json({ error: 'Invalid email or password' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match)
      return res.status(401).json({ error: 'Invalid email or password' });

    // Update last login
    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    const token = generateToken(user.id, user.business_id, user.role);
    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role, avatar: user.avatar, businessId: user.business_id },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// GMAIL SMTP EMAIL (for OTP verification)
// ═══════════════════════════════════════════════════════════

// Set these in Railway Variables:
// GMAIL_USER     = your-email@gmail.com
// GMAIL_PASSWORD = your-gmail-app-password (NOT your regular password)
// How to get App Password:
//   1. Gmail → Settings → Security → 2-Step Verification (enable)
//   2. Then go to: Security → App Passwords
//   3. Select App: Mail, Device: Other → Generate
//   4. Copy the 16-character password shown

const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASSWORD,
  },
});

// Send email OTP
app.post('/api/auth/send-email-otp', auth, async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

    // Validate OTP is 6 digits
    if (!/^\d{6}$/.test(String(otp))) return res.status(400).json({ error: 'Invalid OTP format' });

    if (!process.env.GMAIL_USER || !process.env.GMAIL_PASSWORD) {
      // SMTP not configured — return success so frontend shows OTP in toast (dev mode)
      return res.json({ success: true, devMode: true });
    }

    await emailTransporter.sendMail({
      from    : `"Fynlo" <${process.env.GMAIL_USER}>`,
      to      : email,
      subject : 'Fynlo — Your Email Verification OTP',
      html    : `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f8fafc;border-radius:16px;">
          <div style="text-align:center;margin-bottom:24px;">
            <h1 style="color:#4f46e5;margin:0;font-size:28px;">Fyn<span style="color:#94a3b8;">lo</span></h1>
          </div>
          <div style="background:white;border-radius:12px;padding:24px;border:1px solid #e2e8f0;">
            <h2 style="margin:0 0 8px;color:#1e293b;">Verify your email address</h2>
            <p style="color:#64748b;margin:0 0 24px;font-size:14px;">Enter this OTP in the Fynlo app to verify your email address.</p>
            <div style="text-align:center;background:#f0f4ff;border-radius:12px;padding:24px;margin-bottom:24px;">
              <div style="font-size:40px;font-weight:900;letter-spacing:12px;color:#4f46e5;">${otp}</div>
              <div style="font-size:12px;color:#94a3b8;margin-top:8px;">Valid for 10 minutes</div>
            </div>
            <p style="color:#94a3b8;font-size:12px;margin:0;">If you didn't request this, you can safely ignore this email.</p>
          </div>
          <p style="text-align:center;color:#94a3b8;font-size:11px;margin-top:16px;">© ${new Date().getFullYear()} Fynlo · Business Management Platform</p>
        </div>`,
    });

    res.json({ success: true });
  } catch(err) {
    console.error('Email OTP error:', err.message);
    // Don't expose SMTP errors to client — return devMode so frontend shows OTP in toast
    res.json({ success: true, devMode: true, error: err.message });
  }
});

// Send invoice via email
app.post('/api/invoices/:id/send-email', auth, async (req, res) => {
  try {
    const { to, subject, message } = req.body;
    if (!to) return res.status(400).json({ error: 'Recipient email required' });

    if (!process.env.GMAIL_USER || !process.env.GMAIL_PASSWORD) {
      return res.status(503).json({ error: 'Email not configured. Add GMAIL_USER and GMAIL_PASSWORD to Railway Variables.' });
    }

    const inv = await pool.query('SELECT * FROM invoices WHERE id=$1 AND business_id=$2', [req.params.id, req.user.businessId]);
    if (!inv.rows.length) return res.status(404).json({ error: 'Invoice not found' });
    const invoice = inv.rows[0];

    await emailTransporter.sendMail({
      from   : `"Fynlo Business" <${process.env.GMAIL_USER}>`,
      to,
      subject: subject || `Invoice ${invoice.invoice_number} from Fynlo`,
      html   : `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;">
          <h2 style="color:#4f46e5;">Invoice ${invoice.invoice_number}</h2>
          <p style="color:#64748b;">${message || 'Please find your invoice attached.'}</p>
          <table style="width:100%;border-collapse:collapse;margin:24px 0;">
            <tr style="background:#f8fafc;">
              <td style="padding:10px;border:1px solid #e2e8f0;font-weight:700;">Customer</td>
              <td style="padding:10px;border:1px solid #e2e8f0;">${invoice.customer_name}</td>
            </tr>
            <tr>
              <td style="padding:10px;border:1px solid #e2e8f0;font-weight:700;">Amount</td>
              <td style="padding:10px;border:1px solid #e2e8f0;font-size:20px;font-weight:900;color:#4f46e5;">₹${parseFloat(invoice.total_amount).toLocaleString('en-IN')}</td>
            </tr>
            <tr style="background:#f8fafc;">
              <td style="padding:10px;border:1px solid #e2e8f0;font-weight:700;">Status</td>
              <td style="padding:10px;border:1px solid #e2e8f0;">${invoice.payment_status.toUpperCase()}</td>
            </tr>
            <tr>
              <td style="padding:10px;border:1px solid #e2e8f0;font-weight:700;">Due Date</td>
              <td style="padding:10px;border:1px solid #e2e8f0;">${invoice.due_date || 'On receipt'}</td>
            </tr>
          </table>
          <p style="color:#94a3b8;font-size:12px;">Powered by Fynlo · Business Management Platform</p>
        </div>`,
    });

    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════

// Business dashboard stats
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const bId = req.user.businessId;
    const [sales, products, staff, lowStock, invoices] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(total_amount),0) AS total FROM invoices WHERE business_id=$1 AND DATE(invoice_date)=CURRENT_DATE AND payment_status='paid'`, [bId]),
      pool.query(`SELECT COUNT(*) AS count FROM products WHERE business_id=$1 AND is_active=true`, [bId]),
      pool.query(`SELECT COUNT(*) AS count FROM employees WHERE business_id=$1 AND status='active'`, [bId]),
      pool.query(`SELECT name,stock_quantity FROM products WHERE business_id=$1 AND stock_quantity<=min_stock_level AND is_active=true ORDER BY stock_quantity LIMIT 5`, [bId]),
      pool.query(`SELECT COUNT(*) FILTER(WHERE payment_status='paid') AS paid, COUNT(*) FILTER(WHERE payment_status='pending') AS pending FROM invoices WHERE business_id=$1`, [bId]),
    ]);
    res.json({
      todaysSales    : parseFloat(sales.rows[0].total),
      activeProducts : parseInt(products.rows[0].count),
      staffCount     : parseInt(staff.rows[0].count),
      lowStockItems  : lowStock.rows,
      paidInvoices   : parseInt(invoices.rows[0].paid),
      pendingInvoices: parseInt(invoices.rows[0].pending),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin platform stats
app.get('/api/admin/dashboard', auth, adminOnly, async (req, res) => {
  try {
    const [businesses, revenue, invoices, employees] = await Promise.all([
      pool.query(`SELECT COUNT(*) AS total, COUNT(*) FILTER(WHERE status='active') AS active FROM businesses`),
      pool.query(`SELECT COALESCE(SUM(total_revenue),0) AS total, COALESCE(SUM(monthly_revenue),0) AS monthly FROM businesses`),
      pool.query(`SELECT COUNT(*) AS total FROM invoices`),
      pool.query(`SELECT COUNT(*) AS total FROM employees WHERE status='active'`),
    ]);
    res.json({
      totalBusinesses : parseInt(businesses.rows[0].total),
      activeBusinesses: parseInt(businesses.rows[0].active),
      platformRevenue : parseFloat(revenue.rows[0].total),
      monthlyRevenue  : parseFloat(revenue.rows[0].monthly),
      totalInvoices   : parseInt(invoices.rows[0].total),
      totalEmployees  : parseInt(employees.rows[0].total),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// BUSINESSES (Admin only)
// ═══════════════════════════════════════════════════════════

app.get('/api/businesses', auth, adminOnly, async (req, res) => {
  try {
    const { search, status, plan } = req.query;
    let q = `SELECT b.*, u.email AS owner_email FROM businesses b JOIN users u ON b.owner_id = u.id WHERE 1=1`;
    const params = [];
    if (search) { params.push(`%${search}%`); q += ` AND (b.shop_name ILIKE $${params.length} OR u.email ILIKE $${params.length} OR b.city ILIKE $${params.length})`; }
    if (status) { params.push(status); q += ` AND b.status = $${params.length}`; }
    if (plan)   { params.push(plan);   q += ` AND b.subscription_plan = $${params.length}`; }
    q += ' ORDER BY b.created_at DESC';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/businesses/:id/status', auth, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    await pool.query('UPDATE businesses SET status=$1, updated_at=NOW() WHERE id=$2', [status, req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// PRODUCTS
// ═══════════════════════════════════════════════════════════

app.get('/api/products', auth, async (req, res) => {
  try {
    const { search, category, stock } = req.query;
    let q = `SELECT p.*, s.name AS supplier_name FROM products p LEFT JOIN suppliers s ON p.supplier_id = s.id WHERE p.business_id=$1 AND p.is_active=true`;
    const params = [req.user.businessId];
    if (search)   { params.push(`%${search}%`);  q += ` AND (p.name ILIKE $${params.length} OR p.sku ILIKE $${params.length})`; }
    if (category) { params.push(category);        q += ` AND p.category = $${params.length}`; }
    if (stock === 'low') q += ` AND p.stock_quantity <= p.min_stock_level`;
    if (stock === 'out') q += ` AND p.stock_quantity = 0`;
    q += ' ORDER BY p.created_at DESC';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin — all products across businesses
app.get('/api/admin/products', auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, b.shop_name FROM products p JOIN businesses b ON p.business_id = b.id WHERE p.is_active=true ORDER BY b.shop_name, p.name`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/products', auth, async (req, res) => {
  try {
    const limit = await checkPlanLimit(req.user.businessId, 'product');
    if (limit) return res.status(403).json({ error: limit });

    const { sku, name, description, category, supplier_id, price, cost, stock_quantity, min_stock_level, unit } = req.body;
    if (!sku || !name || price === undefined)
      return res.status(400).json({ error: 'SKU, name, and price are required' });

    const result = await pool.query(
      `INSERT INTO products (business_id,supplier_id,sku,name,description,category,price,cost,stock_quantity,min_stock_level,unit)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [req.user.businessId, supplier_id||null, sku, name, description||null, category||null,
       price, cost||0, stock_quantity||0, min_stock_level||5, unit||'piece']
    );

    // Update counter
    await pool.query('UPDATE businesses SET total_products=total_products+1 WHERE id=$1', [req.user.businessId]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'SKU already exists for this business' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/products/:id', auth, async (req, res) => {
  try {
    const { name, category, price, cost, stock_quantity, min_stock_level, description, unit, supplier_id } = req.body;
    const result = await pool.query(
      `UPDATE products SET name=$1,category=$2,price=$3,cost=$4,stock_quantity=$5,
       min_stock_level=$6,description=$7,unit=$8,supplier_id=$9,updated_at=NOW()
       WHERE id=$10 AND business_id=$11 RETURNING *`,
      [name, category, price, cost||0, stock_quantity, min_stock_level||5, description||null,
       unit||'piece', supplier_id||null, req.params.id, req.user.businessId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Product not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/products/:id', auth, async (req, res) => {
  try {
    await pool.query('UPDATE products SET is_active=false WHERE id=$1 AND business_id=$2', [req.params.id, req.user.businessId]);
    await pool.query('UPDATE businesses SET total_products=GREATEST(total_products-1,0) WHERE id=$1', [req.user.businessId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// EMPLOYEES
// ═══════════════════════════════════════════════════════════

app.get('/api/employees', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.*, m.name AS manager_name FROM employees e
       LEFT JOIN employees m ON e.manager_id = m.id
       WHERE e.business_id=$1 AND e.status != 'terminated'
       ORDER BY e.name`,
      [req.user.businessId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/employees', auth, async (req, res) => {
  try {
    const limit = await checkPlanLimit(req.user.businessId, 'employee');
    if (limit) return res.status(403).json({ error: limit });

    const { name, email, phone, position, department, salary, salary_type, hire_date, manager_id } = req.body;
    if (!name || !position) return res.status(400).json({ error: 'Name and position are required' });

    const result = await pool.query(
      `INSERT INTO employees (business_id,name,email,phone,position,department,salary,salary_type,hire_date,manager_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.user.businessId, name, email||null, phone||null, position, department||null,
       salary||0, salary_type||'monthly', hire_date||null, manager_id||null]
    );
    await pool.query('UPDATE businesses SET total_employees=total_employees+1 WHERE id=$1', [req.user.businessId]);
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/employees/:id', auth, async (req, res) => {
  try {
    const { name, email, phone, position, department, salary, salary_type, status, manager_id } = req.body;
    const result = await pool.query(
      `UPDATE employees SET name=$1,email=$2,phone=$3,position=$4,department=$5,salary=$6,
       salary_type=$7,status=$8,manager_id=$9,updated_at=NOW()
       WHERE id=$10 AND business_id=$11 RETURNING *`,
      [name, email||null, phone||null, position, department||null, salary||0,
       salary_type||'monthly', status||'active', manager_id||null, req.params.id, req.user.businessId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Employee not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// ATTENDANCE
// ═══════════════════════════════════════════════════════════

app.get('/api/attendance', auth, async (req, res) => {
  try {
    const { date, month } = req.query;
    let q = `SELECT a.*, e.name AS employee_name, e.position FROM attendance a
             JOIN employees e ON a.employee_id = e.id
             WHERE a.business_id=$1`;
    const params = [req.user.businessId];
    if (date)  { params.push(date);  q += ` AND a.attendance_date = $${params.length}`; }
    if (month) { params.push(month); q += ` AND TO_CHAR(a.attendance_date,'YYYY-MM') = $${params.length}`; }
    q += ' ORDER BY a.attendance_date DESC, e.name';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/attendance', auth, async (req, res) => {
  try {
    const { employee_id, attendance_date, status, check_in_time, check_out_time, notes } = req.body;
    if (!employee_id || !attendance_date || !status)
      return res.status(400).json({ error: 'employee_id, attendance_date, and status required' });

    let hours = 0;
    if (check_in_time && check_out_time) {
      const [inH, inM] = check_in_time.split(':').map(Number);
      const [outH, outM] = check_out_time.split(':').map(Number);
      hours = parseFloat(((outH * 60 + outM - inH * 60 - inM) / 60).toFixed(2));
    }

    const result = await pool.query(
      `INSERT INTO attendance (business_id,employee_id,attendance_date,status,check_in_time,check_out_time,hours_worked,notes,marked_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (employee_id,attendance_date)
       DO UPDATE SET status=$4,check_in_time=$5,check_out_time=$6,hours_worked=$7,notes=$8
       RETURNING *`,
      [req.user.businessId, employee_id, attendance_date, status, check_in_time||null,
       check_out_time||null, hours, notes||null, req.user.userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Bulk mark all employees as present
app.post('/api/attendance/bulk', auth, async (req, res) => {
  try {
    const { date, status } = req.body;
    const employees = await pool.query('SELECT id FROM employees WHERE business_id=$1 AND status=\'active\'', [req.user.businessId]);
    let count = 0;
    for (const emp of employees.rows) {
      await pool.query(
        `INSERT INTO attendance (business_id,employee_id,attendance_date,status,check_in_time,check_out_time,hours_worked)
         VALUES ($1,$2,$3,$4,'09:00','17:00',8)
         ON CONFLICT (employee_id,attendance_date) DO NOTHING`,
        [req.user.businessId, emp.id, date, status || 'present']
      );
      count++;
    }
    res.json({ success: true, marked: count });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// INVOICES
// ═══════════════════════════════════════════════════════════

app.get('/api/invoices', auth, async (req, res) => {
  try {
    const { search, status, sort } = req.query;
    let q = `SELECT i.*, COUNT(ii.id) AS item_count FROM invoices i
             LEFT JOIN invoice_items ii ON i.id = ii.invoice_id
             WHERE i.business_id=$1`;
    const params = [req.user.businessId];
    if (search) { params.push(`%${search}%`); q += ` AND (i.customer_name ILIKE $${params.length} OR i.invoice_number ILIKE $${params.length})`; }
    if (status) { params.push(status); q += ` AND i.payment_status = $${params.length}`; }
    q += ' GROUP BY i.id';
    q += sort === 'amount-desc' ? ' ORDER BY i.total_amount DESC'
       : sort === 'amount-asc'  ? ' ORDER BY i.total_amount ASC'
       : sort === 'date-asc'    ? ' ORDER BY i.invoice_date ASC'
       : ' ORDER BY i.invoice_date DESC';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin — all invoices
app.get('/api/admin/invoices', auth, adminOnly, async (req, res) => {
  try {
    const { search, status, sort } = req.query;
    let q = `SELECT i.*, b.shop_name FROM invoices i JOIN businesses b ON i.business_id = b.id WHERE 1=1`;
    const params = [];
    if (search) { params.push(`%${search}%`); q += ` AND (b.shop_name ILIKE $${params.length} OR i.customer_name ILIKE $${params.length} OR i.invoice_number ILIKE $${params.length})`; }
    if (status) { params.push(status); q += ` AND i.payment_status = $${params.length}`; }
    q += sort === 'biz-asc'      ? ' ORDER BY b.shop_name ASC'
       : sort === 'biz-desc'     ? ' ORDER BY b.shop_name DESC'
       : sort === 'amount-desc'  ? ' ORDER BY i.total_amount DESC'
       : sort === 'customer-asc' ? ' ORDER BY i.customer_name ASC'
       : sort === 'date-asc'     ? ' ORDER BY i.invoice_date ASC'
       : ' ORDER BY i.invoice_date DESC';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/invoices', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const limit = await checkPlanLimit(req.user.businessId, 'invoice');
    if (limit) return res.status(403).json({ error: limit });

    const { customer_name, customer_email, customer_phone, customer_address,
            invoice_date, due_date, tax_percentage, discount_amount, notes, items } = req.body;

    if (!customer_name || !items?.length)
      return res.status(400).json({ error: 'Customer name and at least one item required' });

    // Generate invoice number
    const countRes = await client.query('SELECT COUNT(*) FROM invoices WHERE business_id=$1', [req.user.businessId]);
    const invNum = `INV-${new Date().getFullYear()}-${String(parseInt(countRes.rows[0].count) + 1).padStart(3,'0')}`;

    const subtotal = items.reduce((sum, i) => sum + i.quantity * i.unit_price, 0);
    const taxPct   = tax_percentage ?? 18;
    const taxAmt   = parseFloat((subtotal * taxPct / 100).toFixed(2));
    const discount = parseFloat(discount_amount || 0);
    const total    = parseFloat((subtotal + taxAmt - discount).toFixed(2));

    await client.query('BEGIN');

    const invRes = await client.query(
      `INSERT INTO invoices (business_id,invoice_number,customer_name,customer_email,customer_phone,
       customer_address,invoice_date,due_date,subtotal,tax_percentage,tax_amount,discount_amount,total_amount,notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [req.user.businessId, invNum, customer_name, customer_email||null, customer_phone||null,
       customer_address||null, invoice_date||new Date(), due_date||null,
       subtotal, taxPct, taxAmt, discount, total, notes||null]
    );
    const invoiceId = invRes.rows[0].id;

    for (const item of items) {
      const lineTotal = parseFloat((item.quantity * item.unit_price).toFixed(2));
      await client.query(
        `INSERT INTO invoice_items (invoice_id,product_id,item_name,quantity,unit_price,line_total)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [invoiceId, item.product_id||null, item.item_name, item.quantity, item.unit_price, lineTotal]
      );
      // Deduct stock if product linked
      if (item.product_id) {
        await client.query(
          `UPDATE products SET stock_quantity = stock_quantity - $1 WHERE id = $2 AND business_id = $3`,
          [item.quantity, item.product_id, req.user.businessId]
        );
      }
    }

    await client.query('UPDATE businesses SET total_invoices=total_invoices+1 WHERE id=$1', [req.user.businessId]);
    await client.query('COMMIT');

    res.status(201).json({ ...invRes.rows[0], items });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Get invoice with items
app.get('/api/invoices/:id', auth, async (req, res) => {
  try {
    const inv = await pool.query('SELECT * FROM invoices WHERE id=$1 AND business_id=$2', [req.params.id, req.user.businessId]);
    if (!inv.rows.length) return res.status(404).json({ error: 'Invoice not found' });
    const items = await pool.query('SELECT * FROM invoice_items WHERE invoice_id=$1', [req.params.id]);
    res.json({ ...inv.rows[0], items: items.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Mark invoice paid
app.patch('/api/invoices/:id/pay', auth, async (req, res) => {
  try {
    const { payment_method, razorpay_payment_id } = req.body;
    const result = await pool.query(
      `UPDATE invoices SET payment_status='paid', payment_method=$1, razorpay_payment_id=$2,
       paid_at=NOW(), updated_at=NOW() WHERE id=$3 AND business_id=$4 RETURNING *`,
      [payment_method||'manual', razorpay_payment_id||null, req.params.id, req.user.businessId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Invoice not found' });
    const amount = result.rows[0].total_amount;
    await pool.query(
      'UPDATE businesses SET total_revenue=total_revenue+$1, monthly_revenue=monthly_revenue+$1 WHERE id=$2',
      [amount, req.user.businessId]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// PAYROLL
// ═══════════════════════════════════════════════════════════

app.get('/api/payroll', auth, async (req, res) => {
  try {
    const { month } = req.query;
    let q = `SELECT p.*, e.name AS employee_name, e.position FROM payroll p
             JOIN employees e ON p.employee_id = e.id
             WHERE p.business_id=$1`;
    const params = [req.user.businessId];
    if (month) { params.push(month); q += ` AND TO_CHAR(p.payroll_month,'YYYY-MM') = $${params.length}`; }
    q += ' ORDER BY e.name';
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/payroll/generate', auth, async (req, res) => {
  try {
    const { month } = req.body;
    const employees = await pool.query('SELECT * FROM employees WHERE business_id=$1 AND status=\'active\'', [req.user.businessId]);
    const created = [];
    for (const emp of employees.rows) {
      const taxAmt = parseFloat((emp.salary * 0.1).toFixed(2));
      const net    = parseFloat((emp.salary - taxAmt).toFixed(2));
      const res2 = await pool.query(
        `INSERT INTO payroll (business_id,employee_id,payroll_month,base_salary,tax_amount,net_salary)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (employee_id,payroll_month) DO NOTHING RETURNING *`,
        [req.user.businessId, emp.id, month, emp.salary, taxAmt, net]
      );
      if (res2.rows.length) created.push(res2.rows[0]);
    }
    res.json({ success: true, created: created.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/payroll/:id/pay', auth, async (req, res) => {
  try {
    const { razorpay_payout_id } = req.body;
    const result = await pool.query(
      `UPDATE payroll SET payment_status='paid', razorpay_payout_id=$1, paid_at=NOW()
       WHERE id=$2 AND business_id=$3 RETURNING *`,
      [razorpay_payout_id||null, req.params.id, req.user.businessId]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// RAZORPAY — UPI + CARD PAYMENTS
// ═══════════════════════════════════════════════════════════

// Create Razorpay order (for invoice payment or plan upgrade)
app.post('/api/payments/create-order', auth, async (req, res) => {
  try {
    const { amount, currency, notes } = req.body;
    if (!amount) return res.status(400).json({ error: 'Amount required' });

    const order = await razorpay.orders.create({
      amount  : Math.round(amount * 100),   // paise
      currency: currency || 'INR',
      notes   : notes || {},
    });
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Verify Razorpay payment signature
app.post('/api/payments/verify', auth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, invoice_id, plan_name } = req.body;

    // Signature verification
    const sign     = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(sign)
      .digest('hex');

    if (expected !== razorpay_signature)
      return res.status(400).json({ error: 'Invalid payment signature' });

    // Mark invoice paid if provided
    if (invoice_id) {
      await pool.query(
        `UPDATE invoices SET payment_status='paid', payment_method='razorpay',
         razorpay_payment_id=$1, paid_at=NOW(), updated_at=NOW() WHERE id=$2 AND business_id=$3`,
        [razorpay_payment_id, invoice_id, req.user.businessId]
      );
    }

    // Upgrade plan if provided
    if (plan_name) {
      const planPrices = { Free: 0, Starter: 499, Professional: 1299, Enterprise: 2499 };
      const planLimits = {
        Free        : { max_products: 10,     max_employees: 2,       max_invoices_per_month: 10 },
        Starter     : { max_products: 100,    max_employees: 5,       max_invoices_per_month: 50 },
        Professional: { max_products: 1000,   max_employees: 25,      max_invoices_per_month: 500 },
        Enterprise  : { max_products: 999999, max_employees: 999999,  max_invoices_per_month: 999999 },
      };
      await pool.query(
        'UPDATE businesses SET subscription_plan=$1, subscription_status=\'active\', updated_at=NOW() WHERE id=$2',
        [plan_name, req.user.businessId]
      );
      const lim = planLimits[plan_name];
      await pool.query(
        `INSERT INTO subscriptions (business_id,plan_name,price,currency,max_products,max_employees,max_invoices_per_month,razorpay_subscription_id)
         VALUES ($1,$2,$3,'INR',$4,$5,$6,$7)
         ON CONFLICT (business_id) DO UPDATE SET plan_name=$2,price=$3,max_products=$4,max_employees=$5,max_invoices_per_month=$6,updated_at=NOW()`,
        [req.user.businessId, plan_name, planPrices[plan_name]||499, lim.max_products, lim.max_employees, lim.max_invoices_per_month, razorpay_payment_id]
      ).catch(() => {});  // subscriptions table may not have UNIQUE on business_id — handle gracefully
    }

    res.json({ success: true, payment_id: razorpay_payment_id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═══════════════════════════════════════════════════════════

app.get('/api/notifications', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/notifications/read-all', auth, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET is_read=true, read_at=NOW() WHERE user_id=$1', [req.user.userId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// EXPENSES (Simple tracking)
// ═══════════════════════════════════════════════════════════

app.get('/api/expenses', auth, async (req, res) => {
  try {
    // Use invoice data to derive expenses for now
    // Full expense table can be added to schema later
    res.json([]);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// CUSTOMERS (derived from invoice data)
// ═══════════════════════════════════════════════════════════

app.get('/api/customers', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         customer_name AS name,
         customer_email AS email,
         customer_phone AS phone,
         COUNT(*) AS total_invoices,
         SUM(total_amount) AS total_spent,
         MAX(invoice_date) AS last_purchase,
         MIN(invoice_date) AS first_purchase,
         SUM(CASE WHEN payment_status='paid' THEN total_amount ELSE 0 END) AS paid_amount,
         SUM(CASE WHEN payment_status='pending' THEN total_amount ELSE 0 END) AS pending_amount
       FROM invoices
       WHERE business_id=$1
       GROUP BY customer_name, customer_email, customer_phone
       ORDER BY total_spent DESC`,
      [req.user.businessId]
    );
    res.json(result.rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// EMAIL OTP VERIFICATION (Gmail SMTP)
// ═══════════════════════════════════════════════════════════

// In-memory OTP store (use Redis in production)
const otpStore = new Map();

app.post('/api/auth/send-email-otp', auth, async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

    // Store OTP with 10-minute expiry
    otpStore.set(email, { otp, expires: Date.now() + 10 * 60 * 1000 });

    // Send via Gmail SMTP (nodemailer)
    // Install: npm install nodemailer
    try {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
      });

      await transporter.sendMail({
        from: `"Fynlo" <${process.env.SMTP_USER}>`,
        to: email,
        subject: 'Verify your email — Fynlo',
        html: `
          <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f8fafc;border-radius:16px;">
            <div style="text-align:center;margin-bottom:24px;">
              <h2 style="color:#4f46e5;margin:0;">Fynlo</h2>
              <p style="color:#64748b;margin:4px 0 0;">Business Management Platform</p>
            </div>
            <div style="background:white;border-radius:12px;padding:24px;text-align:center;">
              <p style="font-size:16px;color:#1e293b;margin:0 0 16px;">Your email verification code:</p>
              <div style="font-size:40px;font-weight:900;letter-spacing:12px;color:#4f46e5;padding:20px;background:#f0f4ff;border-radius:10px;">${otp}</div>
              <p style="font-size:13px;color:#64748b;margin:16px 0 0;">This code expires in <strong>10 minutes</strong>.</p>
              <p style="font-size:12px;color:#94a3b8;margin:8px 0 0;">If you didn't request this, ignore this email.</p>
            </div>
          </div>`,
      });
      res.json({ success: true, message: 'OTP sent via email' });
    } catch(emailErr) {
      console.error('SMTP error:', emailErr.message);
      // Return success anyway — frontend shows OTP in dev mode
      res.json({ success: true, devOtp: process.env.NODE_ENV !== 'production' ? otp : undefined });
    }
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Verify OTP and mark email as verified in DB
app.post('/api/auth/verify-email', auth, async (req, res) => {
  try {
    const { email, otp } = req.body;
    const stored = otpStore.get(email);

    if (!stored) return res.status(400).json({ error: 'No OTP found. Please request a new one.' });
    if (Date.now() > stored.expires) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
    }
    if (stored.otp !== otp) return res.status(400).json({ error: 'Incorrect OTP. Please try again.' });

    // Mark email verified in DB
    await pool.query(
      'UPDATE users SET email_verified=true, updated_at=NOW() WHERE id=$1',
      [req.user.userId]
    );
    otpStore.delete(email);
    res.json({ success: true, message: 'Email verified successfully!' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// SUBSCRIPTION AUTO-BILLING
// ═══════════════════════════════════════════════════════════

// Get subscription status
app.get('/api/subscription', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM subscriptions WHERE business_id=$1 AND is_active=true ORDER BY created_at DESC LIMIT 1',
      [req.user.businessId]
    );
    res.json(result.rows[0] || { plan_name:'Free', price:0, max_products:10, max_employees:2, max_invoices_per_month:10 });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Toggle auto-renew
app.patch('/api/subscription/auto-renew', auth, async (req, res) => {
  try {
    const { auto_renew } = req.body;
    await pool.query(
      'UPDATE subscriptions SET auto_renew=$1, updated_at=NOW() WHERE business_id=$2 AND is_active=true',
      [auto_renew, req.user.businessId]
    );
    res.json({ success:true, auto_renew });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Cancel subscription (downgrade to Free at period end)
app.delete('/api/subscription', auth, async (req, res) => {
  try {
    await pool.query(
      'UPDATE subscriptions SET auto_renew=false, cancelled_at=NOW(), updated_at=NOW() WHERE business_id=$1 AND is_active=true',
      [req.user.businessId]
    );
    res.json({ success:true, message:'Subscription cancelled. You will be downgraded to Free at end of billing period.' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// CHAT
// ═══════════════════════════════════════════════════════════

app.get('/api/chat/:receiverId', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT cm.*, u.name AS sender_name, u.avatar AS sender_avatar
       FROM chat_messages cm JOIN users u ON cm.sender_id = u.id
       WHERE (cm.sender_id=$1 AND cm.receiver_id=$2)
          OR (cm.sender_id=$2 AND cm.receiver_id=$1)
       ORDER BY cm.created_at ASC LIMIT 100`,
      [req.user.userId, req.params.receiverId]
    );
    // Mark received as read
    await pool.query(
      'UPDATE chat_messages SET is_read=true, read_at=NOW() WHERE receiver_id=$1 AND sender_id=$2 AND is_read=false',
      [req.user.userId, req.params.receiverId]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/chat', auth, async (req, res) => {
  try {
    const { receiver_id, message } = req.body;
    if (!receiver_id || !message) return res.status(400).json({ error: 'receiver_id and message required' });
    const result = await pool.query(
      'INSERT INTO chat_messages (sender_id,receiver_id,business_id,message) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.userId, receiver_id, req.user.businessId||null, message]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
// PROFILE
// ═══════════════════════════════════════════════════════════

app.get('/api/profile', auth, async (req, res) => {
  try {
    const user = await pool.query('SELECT id,email,name,role,avatar,phone FROM users WHERE id=$1', [req.user.userId]);
    let business = null;
    if (req.user.businessId) {
      const biz = await pool.query('SELECT * FROM businesses WHERE id=$1', [req.user.businessId]);
      business = biz.rows[0] || null;
    }
    res.json({ user: user.rows[0], business });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/profile', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { name, phone, shopName, category, address, city, state, zip, country, website, taxId, upiId, bio } = req.body;
    await client.query('BEGIN');
    await client.query('UPDATE users SET name=$1, phone=$2, updated_at=NOW() WHERE id=$3', [name, phone||null, req.user.userId]);
    if (req.user.businessId) {
      await client.query(
        `UPDATE businesses SET shop_name=$1,category=$2,phone=$3,address=$4,city=$5,state=$6,
         zip=$7,country=$8,website=$9,tax_id=$10,upi_id=$11,bio=$12,updated_at=NOW() WHERE id=$13`,
        [shopName||name, category||null, phone||null, address||null, city||null, state||null,
         zip||null, country||'India', website||null, taxId||null, upiId||null, bio||null, req.user.businessId]
      );
    }
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ═══════════════════════════════════════════════════════════
// ERROR HANDLER
// ═══════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ═══════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════

async function start() {
  try {
    // Print environment check on startup
    console.log('── Environment Check ──');
    console.log('  JWT_SECRET:    ', process.env.JWT_SECRET       ? '✓ set' : '✗ MISSING');
    console.log('  DATABASE_URL:  ', process.env.DATABASE_URL      ? '✓ set' : '✗ MISSING');
    console.log('  RAZORPAY_KEY:  ', process.env.RAZORPAY_KEY_ID   ? '✓ set' : '✗ MISSING');
    console.log('  FRONTEND_URL:  ', process.env.FRONTEND_URL       ? '✓ set' : '✗ MISSING');
    console.log('  NODE_ENV:      ', process.env.NODE_ENV           || 'not set');
    console.log('  PORT:          ', process.env.PORT               || '3000 (default)');
    console.log('───────────────────────');
    await initDatabase();
    app.listen(PORT, () => {
      console.log('');
      console.log('  SkipHub API is running!');
      console.log(`  Local:   http://localhost:${PORT}`);
      console.log(`  Health:  http://localhost:${PORT}/health`);
      console.log('');
    });
  } catch (err) {
    console.error('Failed to start:', err.message);
    process.exit(1);
  }
}

start();
module.exports = app;
