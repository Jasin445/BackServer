require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');

// Initialize Firebase Admin
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
});

// Initialize Express
const app = express();

// Middleware
app.use(express.json());

// CORS Configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: true
};
app.use(cors(corsOptions));
// app.options('*', cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_PORT === '465',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  }
});

// Verify SMTP connection on startup
transporter.verify((error) => {
  if (error) {
    console.error('SMTP connection error:', error);
  } else {
    console.log('SMTP connection established');
  }
});

// OTP Storage
const otpStorage = {};

// Generate OTP
const generateOTP = () => Math.floor(1000 + Math.random() * 9000).toString();

// Routes

app.get('/', (req, res) => {
    res.send('Hello from your Node.js server!');
  });
  

app.post('/api/send-otp', async (req, res) => {
  const { email, action = 'verify' } = req.body;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  try {
    if (action === 'reset') {
      await admin.auth().getUserByEmail(email);
    }

    const otp = generateOTP();
    const expiresAt = Date.now() + (process.env.OTP_EXPIRY_MINUTES || 5) * 60 * 1000;
    otpStorage[email] = { otp, expiresAt, action };

    await transporter.sendMail({
      from: `"JayJobs" <${process.env.SMTP_USER}>`,
      to: email,
      subject: `Your OTP for ${action === 'verify' ? 'Email Verification' : 'Password Reset'}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Your One-Time Password (OTP)</h2>
          <p>Use this code to ${action === 'verify' ? 'verify your email' : 'reset your password'}:</p>
          <div style="font-size: 24px; font-weight: bold; margin: 20px 0;">${otp}</div>
          <p><small>This OTP expires in ${process.env.OTP_EXPIRY_MINUTES || 5} minutes.</small></p>
        </div>
      `
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ 
      error: action === 'reset' ? 'Email not registered' : 'Failed to send OTP' 
    });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const storedData = otpStorage[email];

  if (!storedData || storedData.otp !== otp) {
    return res.status(400).json({ error: 'Invalid OTP' });
  }

  if (Date.now() > storedData.expiresAt) {
    delete otpStorage[email];
    return res.status(410).json({ error: 'OTP expired' });
  }

  try {
    if (storedData.action === 'verify') {
      await admin.auth().updateUser(
        (await admin.auth().getUserByEmail(email)).uid, 
        { emailVerified: true }
      );
    } else if (storedData.action === 'reset' && newPassword) {
      await admin.auth().updateUser(
        (await admin.auth().getUserByEmail(email)).uid,
        { password: newPassword }
      );
    } else {
      return res.status(400).json({ error: 'Invalid request' });
    }

    delete otpStorage[email];
    res.json({ success: true });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Cleanup job
setInterval(() => {
  const now = Date.now();
  Object.keys(otpStorage).forEach(email => {
    if (otpStorage[email].expiresAt < now) {
      delete otpStorage[email];
    }
  });
}, 60000);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});