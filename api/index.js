import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import fs from 'fs';
import twilio from 'twilio';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MongoDB Setup
let dbInstance = null;
async function connectDB() {
  if (dbInstance) return dbInstance;
  const client = new MongoClient(process.env.DATABASE_URL);
  await client.connect();
  dbInstance = client.db(); // Uses database name from URL
  return dbInstance;
}

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret_key_change_me';

app.use(cors());
app.use(express.json());

// Helper to normalize phone numbers
const normalizePhone = (phone) => {
  if (!phone) return '';
  return phone.replace(/\D/g, ''); // Remove all non-digits
};

// Serve Static Files (Frontend)
app.use(express.static(path.join(__dirname, '../dist'), {
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-store');
  }
}));

// Middleware to authenticate
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// --- SESSION VALIDATION ---
app.post('/api/functions/validateSession', authenticate, async (req, res) => {
  try {
    const db = await connectDB();
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });

    if (!user) {
      return res.status(401).json({ valid: false });
    }

    const userResponse = {
      ...user,
      id: user._id.toString(),
      roles: user.roles ? (typeof user.roles === 'string' ? JSON.parse(user.roles) : user.roles) : [],
      role_prices: user.role_prices ? (typeof user.role_prices === 'string' ? JSON.parse(user.role_prices) : user.role_prices) : {},
      has_password: !!user.password
    };

    res.json({ valid: true, user: userResponse });
  } catch (error) {
    res.status(500).json({ valid: false, error: error.message });
  }
});

// --- USER FUNCTIONS ---

app.post('/api/functions/listWaiters', async (req, res) => {
  try {
    const db = await connectDB();
    const users = await db.collection('users').find({}).toArray();

    const formattedUsers = users.map(u => ({
      ...u,
      id: u._id.toString(),
      roles: u.roles ? (typeof u.roles === 'string' ? JSON.parse(u.roles) : u.roles) : [],
      role_prices: u.role_prices ? (typeof u.role_prices === 'string' ? JSON.parse(u.role_prices) : u.role_prices) : {},
      has_password: !!u.password
    }));
    res.json({ users: formattedUsers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- AUTH ROUTES ---

// Helper
const generateToken = (user) => {
  // Use _id from Mongo doc or id from mapped user
  const userId = user._id ? user._id.toString() : user.id;
  return jwt.sign({ id: userId, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
};

// Initialize Twilio client if credentials are available
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

const twilioClient = accountSid && authToken && twilioPhoneNumber
  ? twilio(accountSid, authToken)
  : null;

// Send Verification Code
app.post('/api/functions/sendVerificationCode', async (req, res) => {
  const { phone: rawPhone } = req.body;
  if (!rawPhone) return res.status(400).json({ error: 'Phone required' });

  const phone = normalizePhone(rawPhone);
  const code = '123456'; // Fixed for dev
  const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

  try {
    const db = await connectDB();
    const users = db.collection('users');

    await users.updateOne(
      { phone },
      {
        $set: {
          verification_code: code,
          verification_code_expires: expires,
          updated_at: new Date()
        },
        $setOnInsert: {
          created_at: new Date(),
          available: true
        }
      },
      { upsert: true }
    );

    console.log(`[TEST MODE] Code for ${phone}: ${code}`);
    res.json({ success: true, development: true, code });

  } catch (error) {
    console.error('Error sending verification code:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Phone Login
app.post('/api/functions/phoneLogin', async (req, res) => {
  const { phone: rawPhone, code } = req.body;
  const phone = normalizePhone(rawPhone);

  try {
    const db = await connectDB();
    const user = await db.collection('users').findOne({ phone });

    if (!user || user.verification_code !== code) {
      return res.status(400).json({ error: 'Invalid code' });
    }

    if (new Date() > new Date(user.verification_code_expires)) {
      return res.status(400).json({ error: 'Code expired' });
    }

    // Clear code
    await db.collection('users').updateOne(
      { _id: user._id },
      { $set: { verification_code: null, verification_code_expires: null } }
    );

    const token = generateToken(user);
    const userResponse = {
      ...user,
      id: user._id.toString(),
      roles: user.roles ? (typeof user.roles === 'string' ? JSON.parse(user.roles) : user.roles) : [],
      role_prices: user.role_prices ? (typeof user.role_prices === 'string' ? JSON.parse(user.role_prices) : user.role_prices) : {},
      has_password: !!user.password
    };

    res.json({ success: true, session_token: token, user: userResponse });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

if (!user || user.verification_code !== code) {
  return res.status(400).json({ error: 'Invalid code' });
}

if (new Date() > user.verification_code_expires) {
  return res.status(400).json({ error: 'Code expired' });
}

// Clear code
await prisma.user.update({
  where: { id: user.id },
  data: { verification_code: null, verification_code_expires: null }
});

const token = generateToken(user);

// Format user for frontend
const userResponse = {
  ...user,
  roles: user.roles ? JSON.parse(user.roles) : [],
  role_prices: user.role_prices ? JSON.parse(user.role_prices) : {},
  has_password: !!user.password
};

res.json({ success: true, session_token: token, user: userResponse });
});

// Password Login
app.post('/api/functions/loginWithPassword', async (req, res) => {
  const { phone: rawPhone, password } = req.body;
  const phone = normalizePhone(rawPhone);
  const user = await prisma.user.findUnique({ where: { phone } });

  if (!user || !user.password) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = generateToken(user);
  // Format user for frontend
  const userResponse = {
    ...user,
    roles: user.roles ? JSON.parse(user.roles) : [],
    role_prices: user.role_prices ? JSON.parse(user.role_prices) : {},
    has_password: !!user.password
  };

  res.json({ success: true, session_token: token, user: userResponse });
});

// Password Reset Endpoints (Missing and called by frontend)
app.post('/api/functions/requestPasswordReset', async (req, res) => {
  const { phone: rawPhone } = req.body;
  const phone = normalizePhone(rawPhone);
  const user = await prisma.user.findUnique({ where: { phone } });

  if (!user) {
    // For security, don't reveal if user exists
    return res.json({ success: true, message: 'If account exists, reset instructions sent.' });
  }

  // Generate a code/token (recycling verification_code for now)
  const token = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = new Date(Date.now() + 30 * 60 * 1000); // 30 mins

  await prisma.user.update({
    where: { id: user.id },
    data: { verification_code: token, verification_code_expires: expires }
  });

  // In a real app, send email. Here, we just return it or log it.
  console.log(`[PASSWORD RESET] Token for ${phone}: ${token}`);

  res.json({
    success: true,
    message: 'Reset instructions sent',
    development: true,
    token: token // Sending token back for demo purposes as requested by frontend flow
  });
});

app.post('/api/functions/resetPassword', async (req, res) => {
  const { token, new_password } = req.body;

  const user = await prisma.user.findFirst({
    where: {
      verification_code: token,
      verification_code_expires: { gt: new Date() }
    }
  });

  if (!user) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  const hashedPassword = await bcrypt.hash(new_password, 10);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      password: hashedPassword,
      verification_code: null,
      verification_code_expires: null
    }
  });

  res.json({ success: true, message: 'Password updated successfully' });
});

// --- USER ROUTES ---

app.post('/api/functions/updateUserProfile', authenticate, async (req, res) => {
  console.log('Update Request Received:', req.body);
  const { user_id, data, hash_password } = req.body;

  // Authorization check
  if (parseInt(user_id) !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  // Whitelist fields to avoid Prisma errors with unknown fields
  const allowedFields = [
    'phone', 'full_name', 'email', 'profile_image', 'roles',
    'city', 'region', 'price_per_event', 'role_prices',
    'bio', 'experience_years', 'available', 'password'
  ];

  const updateData = {};
  Object.keys(data).forEach(key => {
    if (allowedFields.includes(key)) {
      updateData[key] = data[key];
    }
  });

  if (hash_password && updateData.password) {
    updateData.password = await bcrypt.hash(updateData.password, 10);
    // Removed: updateData.has_password = true; (Field not in schema)
  }

  // Handle JSON fields
  if (updateData.roles && typeof updateData.roles !== 'string') {
    updateData.roles = JSON.stringify(updateData.roles);
  }
  if (updateData.role_prices && typeof updateData.role_prices !== 'string') {
    updateData.role_prices = JSON.stringify(updateData.role_prices);
  }

  // Ensure types are correct for Prisma/MySQL
  if (updateData.experience_years !== undefined) {
    updateData.experience_years = parseInt(updateData.experience_years) || 0;
  }
  if (updateData.price_per_event !== undefined) {
    updateData.price_per_event = parseFloat(updateData.price_per_event) || 0;
  }

  try {
    const updatedUser = await prisma.user.update({
      where: { id: parseInt(user_id) },
      data: updateData
    });

    const userResponse = {
      ...updatedUser,
      roles: updatedUser.roles ? JSON.parse(updatedUser.roles) : [],
      role_prices: updatedUser.role_prices ? JSON.parse(updatedUser.role_prices) : {},
      has_password: !!updatedUser.password
    };

    res.json(userResponse);
  } catch (e) {
    console.error('Update Error:', e);
    res.status(500).json({ error: 'Update failed: ' + e.message });
  }
});

// --- ENTITIES ---

app.get('/api/entities/JobRequest', authenticate, async (req, res) => {
  const { waiter_id, event_manager_id } = req.query;
  const userId = req.user.id;

  // Security: Force filter to only allow user to see their own jobs
  let where = {
    OR: [
      { waiter_id: userId },
      { event_manager_id: userId }
    ]
  };

  // Allow further refinement if requested, but only within their allowed scope
  if (waiter_id && !isNaN(parseInt(waiter_id))) {
    where.AND = (where.AND || []).concat({ waiter_id: parseInt(waiter_id) });
  }
  if (event_manager_id && !isNaN(parseInt(event_manager_id))) {
    where.AND = (where.AND || []).concat({ event_manager_id: parseInt(event_manager_id) });
  }

  try {
    const jobs = await prisma.jobRequest.findMany({
      where,
      include: {
        waiter: { select: { full_name: true, phone: true } },
        event_manager: { select: { full_name: true, phone: true } }
      },
      orderBy: { created_date: 'desc' }
    });

    // Map to flat structure expected by frontend
    const mappedJobs = jobs.map(j => ({
      ...j,
      waiter_name: j.waiter?.full_name,
      waiter_phone: j.waiter?.phone,
      event_manager_name: j.event_manager?.full_name,
      event_manager_phone: j.event_manager?.phone
    }));

    res.json(mappedJobs);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/entities/JobRequest', authenticate, async (req, res) => {
  const { waiter_id, event_manager_id, event_date, event_location, price_offered, event_type, notes, requested_role } = req.body;

  if (!waiter_id || !event_manager_id || !event_date || !price_offered || !requested_role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Security check: Ensure the creator is one of the parties (usually the manager initiating it)
  // For simplicity in this demo, we assume the logged in user is the event_manager_id, 
  // but strictly we should check:
  if (req.user.id !== parseInt(event_manager_id) && req.user.id !== parseInt(waiter_id)) {
    return res.status(403).json({ error: 'Unauthorized to create job for other users' });
  }

  try {
    const newJob = await prisma.jobRequest.create({
      data: {
        waiter_id: parseInt(waiter_id),
        event_manager_id: parseInt(event_manager_id),
        event_date: new Date(event_date),
        event_location,
        price_offered: parseFloat(price_offered),
        event_type,
        notes,
        requested_role,
        status: 'pending'
      }
    });
    res.json(newJob);
  } catch (e) {
    console.error('Create Job Error:', e);
    res.status(500).json({ error: 'Failed to create job request: ' + e.message });
  }
});

app.post('/api/functions/updateJobRequestStatus', authenticate, async (req, res) => {
  const { job_request_id, status, cancellation_reason } = req.body;

  if (!job_request_id || isNaN(parseInt(job_request_id))) {
    return res.status(400).json({ error: 'Invalid Job Request ID' });
  }

  try {
    // Security: Check ownership before update
    const job = await prisma.jobRequest.findUnique({ where: { id: parseInt(job_request_id) } });
    if (!job) return res.status(404).json({ error: 'Job not found' });

    if (job.waiter_id !== req.user.id && job.event_manager_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const updated = await prisma.jobRequest.update({
      where: { id: parseInt(job_request_id) },
      data: { status, cancellation_reason }
    });
    res.json(updated);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// --- CARDCOM PAYMENT INTEGRATION ---
const CARDCOM_API_URL = 'https://secure.cardcom.solutions/api/v11/LowProfile/Create';
const CARDCOM_TERMINAL = process.env.CARDCOM_TERMINAL_NUMBER || '1000';
const CARDCOM_API_NAME = process.env.CARDCOM_API_NAME || 'cardtest1994';
const CARDCOM_SUCCESS_URL = process.env.CARDCOM_SUCCESS_URL || 'http://localhost:5173/payment/success';
const CARDCOM_FAILED_URL = process.env.CARDCOM_FAILED_URL || 'http://localhost:5173/payment/failed';
const CARDCOM_WEBHOOK_URL = process.env.CARDCOM_WEBHOOK_URL || '';

// Create Cardcom Payment Link (returns iframe URL)
app.post('/api/functions/createCardcomPaymentLink', authenticate, async (req, res) => {
  const { job_request_id, amount, customer_name, customer_email } = req.body;

  if (!job_request_id || isNaN(parseInt(job_request_id))) {
    return res.status(400).json({ error: 'Invalid Job Request ID' });
  }

  if (!amount || isNaN(parseFloat(amount))) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  try {
    // Security: Check user is involved in this job
    const job = await prisma.jobRequest.findUnique({
      where: { id: parseInt(job_request_id) },
      include: { event_manager: true, waiter: true }
    });

    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.event_manager_id !== req.user.id && job.waiter_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Prepare Cardcom request
    const cardcomPayload = {
      TerminalNumber: parseInt(CARDCOM_TERMINAL),
      ApiName: CARDCOM_API_NAME,
      ReturnValue: `JOB_${job_request_id}`,
      Amount: parseFloat(amount),
      SuccessRedirectUrl: `${CARDCOM_SUCCESS_URL}?job_id=${job_request_id}`,
      FailedRedirectUrl: `${CARDCOM_FAILED_URL}?job_id=${job_request_id}`,
      WebHookUrl: CARDCOM_WEBHOOK_URL || undefined,
      Document: {
        Name: customer_name || job.event_manager?.full_name || 'לקוח',
        Email: customer_email || job.event_manager?.email || '',
        Products: [
          {
            Description: `עמלת פלטפורמה - הזמנה #${job_request_id}`,
            UnitCost: parseFloat(amount)
          }
        ]
      }
    };

    console.log('Cardcom Request:', JSON.stringify(cardcomPayload, null, 2));

    // Call Cardcom API
    const response = await fetch(CARDCOM_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(cardcomPayload)
    });

    const cardcomResponse = await response.json();
    console.log('Cardcom Response:', cardcomResponse);

    if (cardcomResponse.ResponseCode !== 0) {
      return res.status(400).json({
        error: 'Cardcom error',
        details: cardcomResponse.Description || 'Payment creation failed'
      });
    }

    // Return the iframe URL
    res.json({
      success: true,
      iframe_url: cardcomResponse.Url,
      low_profile_code: cardcomResponse.LowProfileCode,
      job_request_id: job_request_id
    });

  } catch (e) {
    console.error('Cardcom Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Cardcom Webhook Handler (receives payment notifications)
app.post('/api/webhooks/cardcom', async (req, res) => {
  console.log('Cardcom Webhook received:', req.body);

  try {
    const { ReturnValue, ResponseCode, LowProfileCode } = req.body;

    // Extract job_request_id from ReturnValue (format: JOB_123)
    const jobIdMatch = ReturnValue?.match(/JOB_(\d+)/);
    if (!jobIdMatch) {
      console.error('Invalid ReturnValue format:', ReturnValue);
      return res.status(400).json({ error: 'Invalid ReturnValue' });
    }

    const job_request_id = parseInt(jobIdMatch[1]);

    if (ResponseCode === 0) {
      // Payment successful - update job status
      await prisma.jobRequest.update({
        where: { id: job_request_id },
        data: { status: 'paid' }
      });
      console.log(`Job ${job_request_id} marked as paid`);
    } else {
      console.log(`Payment failed for job ${job_request_id}:`, ResponseCode);
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Webhook Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// --- PAYMENTS (MOCK for invoice generation) ---
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.post('/api/functions/createCardcomPayment', authenticate, async (req, res) => {
  const { job_request_id, platform_fee } = req.body;

  if (!job_request_id || isNaN(parseInt(job_request_id))) {
    return res.status(400).json({ error: 'Invalid Job Request ID' });
  }

  try {
    // 1. Update Job Request to 'paid'
    // Security: Check user is involved
    const jobCheck = await prisma.jobRequest.findUnique({
      where: { id: parseInt(job_request_id) },
      include: { event_manager: true, waiter: true }
    });

    if (!jobCheck) return res.status(404).json({ error: 'Job not found' });
    if (jobCheck.event_manager_id !== req.user.id && jobCheck.waiter_id !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const job = await prisma.jobRequest.update({
      where: { id: parseInt(job_request_id) },
      data: { status: 'paid' },
      include: {
        event_manager: true,
        waiter: true
      }
    });

    // 2. Generate Invoice HTML
    const invoiceNum = Math.floor(100000 + Math.random() * 900000);
    const date = new Date().toLocaleDateString('he-IL');

    // Sanitize inputs to prevent XSS
    const managerName = escapeHtml(job.event_manager.full_name || '');
    const managerPhone = escapeHtml(job.event_manager.phone || '');
    const managerEmail = escapeHtml(job.event_manager.email || '');
    const waiterName = escapeHtml(job.waiter.full_name || '');

    const invoiceHtml = `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; direction: rtl; padding: 40px; max-width: 800px; margin: 0 auto; border: 1px solid #eee; background: white; color: #333;">
        <div style="border-bottom: 2px solid #D4AF37; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center;">
          <div>
             <h1 style="color: #D4AF37; margin: 0; font-size: 32px;">חשבונית מס / קבלה</h1>
             <p style="margin: 5px 0; color: #666;">מספר: #${invoiceNum}</p>
          </div>
          <div style="text-align: left;">
            <h2 style="margin: 0; color: #333;">שירות מלצרות</h2>
            <p style="margin: 5px 0; font-size: 14px;">ח.פ. 511234567</p>
            <p style="margin: 0; font-size: 14px;">תל אביב, ישראל</p>
          </div>
        </div>

        <div style="margin-bottom: 40px;">
          <div style="display: flex; justify-content: space-between;">
            <div style="width: 48%;">
              <h3 style="border-bottom: 1px solid #ddd; padding-bottom: 10px; color: #D4AF37;">לכבוד</h3>
              <p style="font-weight: bold; margin-bottom: 5px;">${managerName}</p>
              <p style="margin: 0;">${managerPhone}</p>
              <p style="margin: 0;">${managerEmail}</p>
            </div>
            <div style="width: 48%;">
              <h3 style="border-bottom: 1px solid #ddd; padding-bottom: 10px; color: #D4AF37;">פרטי העסקה</h3>
              <p><strong>תאריך:</strong> ${date}</p>
              <p><strong>עבור:</strong> תיווך שירותי מלצרות</p>
              <p><strong>מספר הזמנה:</strong> ${job.id}</p>
            </div>
          </div>
        </div>

        <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
          <thead>
            <tr style="background-color: #f9f9f9;">
              <th style="text-align: right; padding: 15px; border-bottom: 2px solid #ddd;">תיאור</th>
              <th style="text-align: left; padding: 15px; border-bottom: 2px solid #ddd;">כמות</th>
              <th style="text-align: left; padding: 15px; border-bottom: 2px solid #ddd;">מחיר</th>
              <th style="text-align: left; padding: 15px; border-bottom: 2px solid #ddd;">סה"כ</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style="padding: 15px; border-bottom: 1px solid #ddd;">עמלת פלטפורמה - חיבור לעובד (${waiterName})</td>
              <td style="text-align: left; padding: 15px; border-bottom: 1px solid #ddd;">1</td>
              <td style="text-align: left; padding: 15px; border-bottom: 1px solid #ddd;">₪${platformFee}</td>
              <td style="text-align: left; padding: 15px; border-bottom: 1px solid #ddd;">₪${platformFee}</td>
            </tr>
          </tbody>
        </table>

        <div style="text-align: left; margin-top: 20px;">
          <p style="font-size: 18px; margin: 5px 0;">סה"כ לפני מע"מ: ₪${(platform_fee / 1.17).toFixed(2)}</p>
          <p style="font-size: 18px; margin: 5px 0;">מע"מ (17%): ₪${(platform_fee - (platform_fee / 1.17)).toFixed(2)}</p>
          <h2 style="font-size: 24px; color: #D4AF37; margin-top: 10px;">סה"כ לתשלום: ₪${platform_fee}</h2>
        </div>

        <div style="margin-top: 60px; text-align: center; color: #888; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px;">
          <p>תודה שבחרת בשירות מלצרות! המסמך מופק באופן ממוחשב ואינו דורש חתימה.</p>
        </div>
      </div>
    `;

    res.json({ success: true, invoice_html: invoiceHtml });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});



app.post('/api/entities/Rating', authenticate, async (req, res) => {
  const { job_request_id, waiter_id, event_manager_id, rating, review } = req.body;

  if (!job_request_id || !waiter_id || !event_manager_id || !rating) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const newRating = await prisma.rating.create({
      data: {
        job_request_id: parseInt(job_request_id),
        waiter_id: parseInt(waiter_id),
        event_manager_id: parseInt(event_manager_id),
        rating: parseInt(rating),
        review
      }
    });

    res.json(newRating);
  } catch (e) {
    if (e.code === 'P2002') {
      return res.status(400).json({ error: 'This job has already been rated.' });
    }
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/entities/Rating', authenticate, async (req, res) => {
  const { waiter_id, event_manager_id } = req.query;
  let where = {};
  if (waiter_id && !isNaN(parseInt(waiter_id))) where.waiter_id = parseInt(waiter_id);
  if (event_manager_id && !isNaN(parseInt(event_manager_id))) where.event_manager_id = parseInt(event_manager_id);

  const ratings = await prisma.rating.findMany({
    where,
    include: {
      event_manager: { select: { full_name: true } }
    }
  });

  // Map for frontend
  const mapped = ratings.map(r => ({
    ...r,
    event_manager_name: r.event_manager?.full_name
  }));

  res.json(mapped);
});


// --- FILE UPLOAD ---

// Ensure uploads directory exists

const uploadDir = process.env.VERCEL ? path.join('/tmp', 'uploads') : path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Serve uploaded files statically
app.use('/uploads', express.static(uploadDir));

// Configure Multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const upload = multer({ storage: storage });

app.post('/api/integrations/Core/UploadFile', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // Construct URL. In production, use your actual domain/IP.
  // For now, we return a relative path which the frontend or browser resolves.
  // If the frontend needs a full URL, we might need to verify that.
  // Assuming relative '/uploads/filename' works.
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({ file_url: fileUrl });
});


// CATCH-ALL ROUTE (For React Router)
// This must be AFTER all API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Export app for Vercel
export default app;

if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT} (exposed)`);
  });
}

