// ============================================
// FIREBASE SETUP
// ============================================
const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore(); // This is your database
// ============================================
// PLAN RULES — Edit these any time
// ============================================
const PLANS = {
  free: {
    scansPerDay: 2,          // Free users get 2 scans per day
    showDetailedFlags: false, // Free users see basic results only
    showHistory: false,       // Free users can't see scan history
    canCheckPhones: true,     // Free users CAN check phones
    canCheckUsernames: true,  // Free users CAN check usernames
    canCheckURLs: true,       // Free users CAN check URLs
  },
  premium: {
    scansPerDay: 999,         // Unlimited (effectively)
    showDetailedFlags: true,  // Full details shown
    showHistory: true,        // Full scan history
    canCheckPhones: true,
    canCheckUsernames: true,
    canCheckURLs: true,
  }
};
// ============================================
// AUTH MIDDLEWARE — Checks who is logged in
// ============================================
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  // If no login token was sent, treat as anonymous/guest
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    req.plan = 'free';
    return next();
  }

  try {
    // Verify the token Firebase gave the user
    const token = authHeader.split('Bearer ')[1];
    const decoded = await admin.auth().verifyIdToken(token);

    // Look up this user's profile in the database
    const userDoc = await db.collection('users').doc(decoded.uid).get();

    if (!userDoc.exists) {
      // First time user — create their profile automatically
      await db.collection('users').doc(decoded.uid).set({
        email: decoded.email,
        plan: 'free',
        scansToday: 0,
        lastScanDate: new Date().toDateString(),
        totalScans: 0,
        createdAt: new Date()
      });
      req.user = { uid: decoded.uid, email: decoded.email, plan: 'free' };
    } else {
      req.user = { uid: decoded.uid, email: decoded.email, ...userDoc.data() };
    }

    req.plan = req.user.plan || 'free';
    next();

  } catch (error) {
    // Bad token — treat as guest
    req.user = null;
    req.plan = 'free';
    next();
  }
}
// ============================================
// USAGE TRACKER — Counts daily scans per user
// ============================================
async function checkAndTrackScan(req, res) {
  // If not logged in, allow but don't track
  if (!req.user) {
    return { allowed: true, scansToday: 1, limit: PLANS.free.scansPerDay };
  }

  const uid = req.user.uid;
  const today = new Date().toDateString();
  const userRef = db.collection('users').doc(uid);
  const userData = req.user;
  const plan = PLANS[req.plan] || PLANS.free;

  // Reset counter if it's a new day
  let scansToday = userData.lastScanDate === today ? (userData.scansToday || 0) : 0;

  // Check if user has hit their daily limit
  if (scansToday >= plan.scansPerDay) {
    return {
      allowed: false,
      scansToday,
      limit: plan.scansPerDay,
      message: `Daily limit reached. Upgrade to Premium for unlimited scans.`
    };
  }

  // Increment the counter
  scansToday += 1;
  await userRef.update({
    scansToday,
    lastScanDate: today,
    totalScans: admin.firestore.FieldValue.increment(1)
  });

  return { allowed: true, scansToday, limit: plan.scansPerDay };
}
// ============================================
// TRUSTSHIELD BACKEND SERVER
// Your app's brain — handles all API calls
// ============================================

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Allow your frontend to talk to this backend
app.use(cors());
app.use(express.json());

// ============================================
// TEST ROUTE — Check if server is working
// ============================================
app.get('/', (req, res) => {
  res.json({ message: '✅ TrustShield backend is running!' });
});

// ============================================
// ROUTE: Get current user's profile + usage
// ============================================
app.get('/me', authenticate, async (req, res) => {
  if (!req.user) {
    return res.json({
      loggedIn: false,
      plan: 'free',
      scansToday: 0,
      limit: PLANS.free.scansPerDay
    });
  }

  const today = new Date().toDateString();
  const scansToday = req.user.lastScanDate === today ? (req.user.scansToday || 0) : 0;
  const plan = PLANS[req.plan] || PLANS.free;

  res.json({
    loggedIn: true,
    email: req.user.email,
    plan: req.plan,
    scansToday,
    limit: plan.scansPerDay,
    features: plan
  });
});


// ============================================
// ROUTE: Get user's scan history
// ============================================
app.get('/history', authenticate, async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Please log in to view history.' });
  }

  if (!PLANS[req.plan].showHistory) {
    return res.status(403).json({
      error: 'Scan history is a Premium feature.',
      upgrade: true
    });
  }

  const scans = await db.collection('scans')
    .where('uid', '==', req.user.uid)
    .orderBy('createdAt', 'desc')
    .limit(50)
    .get();

  const history = scans.docs.map(doc => doc.data());
  res.json({ history });
});


// ============================================
// ROUTE: Upgrade user to premium (future Stripe)
// This is a placeholder — Stripe connects here later
// ============================================
app.post('/upgrade', authenticate, async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Please log in first.' });
  }

  // 🔮 FUTURE: Stripe payment verification goes here
  // For now, this manually upgrades a user (for testing)
  await db.collection('users').doc(req.user.uid).update({
    plan: 'premium'
  });

  res.json({
    success: true,
    message: 'Upgraded to Premium!',
    note: 'In production, Stripe will call this route after payment.'
  });
});

// ============================================
// ROUTE 1: URL CHECKER
// Sends the URL to VirusTotal and returns results
// ============================================
app.post('/check-url', authenticate, async (req, res) => {
  const { url } = req.body;
console.log("API KEY:", process.env.VIRUSTOTAL_API_KEY);

  if (!url) {
    return res.status(400).json({ error: 'Please provide a URL.' });
  }
  // Ensure plan is always defined
  req.plan = req.plan || (req.user?.plan || 'free');

  // Check if user is allowed to scan
  const usage = await checkAndTrackScan(req, res);
  if (!usage.allowed) {
    return res.status(429).json({
      error: usage.message,
      scansToday: usage.scansToday,
      limit: usage.limit,
      upgrade: true  // Frontend uses this to show upgrade button
    });
  }
  try {
    // Step 1: Submit URL to VirusTotal for scanning
    const submitResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const analysisId = submitResponse.data.data.id;

    // Step 2: Wait 4 seconds for VirusTotal to finish scanning
    await new Promise(resolve => setTimeout(resolve, 8000));

    // Step 3: Fetch the scan results
    const resultResponse = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
      }
    );

    const stats = resultResponse.data.data.attributes.stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const total = malicious + suspicious + harmless + (stats.undetected || 0);

    // Step 4: Calculate trust score
    const trustScore = Math.max(0, 100 - (malicious * 10) - (suspicious * 3));

    // Step 5: Give a verdict
    let verdict;
    if (malicious > 3) verdict = 'SCAM';
    else if (malicious > 0 || suspicious > 2) verdict = 'RISKY';
    else verdict = 'SAFE';

    // Step 6: Send results back to frontend
     const result = {
      trustScore,
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      totalCheckers: total,
      verdict,
      flags: malicious > 0
        ? [`${malicious} security engines flagged this URL`]
        : [],
      // Only premium users get detailed breakdown
      details: PLANS[req.plan || 'free'].showDetailedFlags
        ? { stats, analysisId }
        : null,
      usage: {
        scansToday: usage.scansToday,
        limit: usage.limit,
        plan: req.plan || 'free'
      }
    };

    // Save to scan history if user is logged in
    if (req.user) {
      await db.collection('scans').add({
        uid: req.user.uid,
        type: 'url',
        input: url,
        trustScore,
        verdict,
        createdAt: new Date()
      });
    }

    res.json(result);

  } catch (error) {
    console.error('URL check error:', error.message);
    res.status(500).json({ error: 'Could not scan this URL.' });
  }
});

// ============================================
// ROUTE 2: PHONE NUMBER CHECKER
// Sends the phone number to NumVerify
// ============================================
app.post('/check-phone', authenticate, async (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ error: 'Please provide a phone number.' });
  }
 // Ensure plan is always defined
  req.plan = req.plan || (req.user?.plan || 'free');

  // Check usage limits
  const usage = await checkAndTrackScan(req, res);
  if (!usage.allowed) {
    return res.status(429).json({
      error: usage.message,
      scansToday: usage.scansToday,
      limit: usage.limit,
      upgrade: true
    });
  }

  try {
    const response = await axios.get('http://apilayer.net/api/validate', {
      params: {
        access_key: process.env.NUMVERIFY_API_KEY,
        number: phone
      }
    });

    const info = response.data;
    let trustScore = 100;
    let flags = [];

    // Deduct points for suspicious signals
    if (!info.valid) {
      trustScore -= 60;
      flags.push('This number appears to be invalid');
    }

    if (info.line_type === 'voip') {
      trustScore -= 30;
      flags.push('VOIP number — very commonly used by scammers');
    }

    if (!info.carrier) {
      trustScore -= 20;
      flags.push('No carrier information found — suspicious');
    }

    if (info.line_type === 'premium_rate') {
      trustScore -= 25;
      flags.push('Premium rate number — often used in scams');
    }

    trustScore = Math.max(0, trustScore);

    let verdict;
    if (trustScore < 40) verdict = 'HIGH RISK';
    else if (trustScore < 70) verdict = 'SUSPICIOUS';
    else verdict = 'LIKELY SAFE';

     const result = {
      trustScore,
      verdict,
      flags: flags || [],
      details: null,
      usage: {
        scansToday: usage.scansToday,
        limit: usage.limit,
        plan: req.plan
      }
    };

    // Save scan history
    if (req.user) {
      const db = admin.firestore();

      await db.collection('scans').add({
        uid: req.user.uid,
        type: 'phone',
        input: phone,
        trustScore,
        verdict,
        createdAt: new Date()
      });
    }

    res.json(result);

  } catch (error) {
    console.error('Phone check error:', error.message);
    res.status(500).json({ error: 'Could not check this phone number.' });
  }
});


// ============================================
// ROUTE 3: USERNAME CHECKER
// Pure logic — no API needed
// ============================================
app.post('/check-username', authenticate, async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Please provide a username.' });
  }

   // Ensure plan is always defined
  req.plan = req.plan || (req.user?.plan || 'free');

  // Check usage limits
  const usage = await checkAndTrackScan(req, res);
  if (!usage.allowed) {
    return res.status(429).json({
      error: usage.message,
      scansToday: usage.scansToday,
      limit: usage.limit,
      upgrade: true
    });
  }

  let trustScore = 100;
  let flags = [];

  // Check 1: Too many numbers in a row
  if (/\d{4,}/.test(username)) {
    trustScore -= 25;
    flags.push('Contains a string of numbers — common bot/fake account pattern');
  }

  // Check 2: Multiple underscores
  if (/_{2,}/.test(username)) {
    trustScore -= 15;
    flags.push('Multiple underscores detected — suspicious pattern');
  }

  // Check 3: Very short username
  if (username.length < 4) {
    trustScore -= 20;
    flags.push('Username is unusually short');
  }

  // Check 4: Very long username
  if (username.length > 30) {
    trustScore -= 10;
    flags.push('Username is unusually long');
  }

  // Check 5: Mimics known brands or official accounts
  const dangerWords = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google',
    'facebook', 'instagram', 'tiktok', 'support', 'official',
    'verify', 'secure', 'helpdesk', 'admin', 'billing',
    'refund', 'customer_care', 'winner', 'giveaway'
  ];

  const lowerUsername = username.toLowerCase();
  dangerWords.forEach(word => {
    if (lowerUsername.includes(word)) {
      trustScore -= 35;
      flags.push(`Contains "${word}" — high risk impersonation pattern`);
    }
  });

  // Check 6: Name + numbers only pattern (e.g. john2847)
  if (/^[a-zA-Z]+\d+$/.test(username)) {
    trustScore -= 20;
    flags.push('Simple name + numbers pattern — common fake account format');
  }

  // Check 7: Random-looking character mix
  if (/[^a-zA-Z0-9_.]/.test(username)) {
    trustScore -= 15;
    flags.push('Contains unusual special characters');
  }

  trustScore = Math.max(0, trustScore);

  let verdict;
  if (trustScore < 40) verdict = 'FAKE/BOT';
  else if (trustScore < 70) verdict = 'SUSPICIOUS';
  else verdict = 'LIKELY REAL';

   const result = {
  trustScore,
  verdict,
  flags: flags || [],
  details: null,
  usage: {
    scansToday: usage.scansToday,
    limit: usage.limit,
    plan: req.plan
  }
};

// Save scan history
if (req.user) {
  const db = admin.firestore();

  await db.collection('scans').add({
    uid: req.user.uid,
    type: 'username',
    input: username,
    trustScore,
    verdict,
    createdAt: new Date()
  });
}

res.json(result);
});

// ============================================
// START THE SERVER
// ============================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ TrustShield backend running on http://localhost:${PORT}`);
  console.log(`📋 Test it: http://localhost:${PORT}`);
});