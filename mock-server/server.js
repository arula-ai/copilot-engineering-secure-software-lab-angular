/**
 * Mock Server for Angular Security Lab
 *
 * This server provides endpoints for demonstrating security concepts.
 * It simulates both vulnerable and secure behaviors for educational purposes.
 *
 * Run with: npm run mock-server
 */

const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('mock-server/db.json');
const middlewares = jsonServer.defaults();

// Enable CORS for development
server.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:4200');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-XSRF-TOKEN');

  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

server.use(middlewares);
server.use(jsonServer.bodyParser);

// ============================================
// Authentication Endpoints
// ============================================

// Vulnerable Login - logs credentials, returns token in response
server.post('/api/vulnerable/login', (req, res) => {
  const { email, password } = req.body;

  // VULNERABLE: Logging credentials!
  console.log('VULNERABLE: Credentials logged:', { email, password });

  // VULNERABLE: Returning JWT in response body (can be stolen via XSS)
  const fakeToken = Buffer.from(JSON.stringify({
    sub: 'usr_001',
    email,
    role: email.includes('admin') ? 'admin' : 'user',
    exp: Date.now() + 3600000
  })).toString('base64');

  res.json({
    token: `fake.${fakeToken}.signature`,
    user: { id: 'usr_001', email, role: 'user' }
  });
});

// Secure Login - sets HttpOnly cookie
server.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  // SECURE: Not logging credentials

  // SECURE: Setting HttpOnly cookie (simulated)
  res.cookie('session', 'secure_session_token_' + Date.now(), {
    httpOnly: true,
    secure: false, // Set to true in production with HTTPS
    sameSite: 'strict',
    maxAge: 3600000
  });

  // Set XSRF token cookie (readable by JavaScript)
  res.cookie('XSRF-TOKEN', 'xsrf_' + Math.random().toString(36).substr(2), {
    httpOnly: false,
    secure: false,
    sameSite: 'strict',
    maxAge: 3600000
  });

  res.json({
    user: {
      id: 'usr_001',
      email,
      role: email.includes('admin') ? 'admin' : 'user'
    }
    // Note: No token in response - it's in the HttpOnly cookie
  });
});

// Secure Logout - clears cookies
server.post('/api/auth/logout', (req, res) => {
  res.clearCookie('session');
  res.clearCookie('XSRF-TOKEN');
  res.json({ success: true });
});

// Session validation
server.get('/api/auth/session', (req, res) => {
  const sessionCookie = req.cookies?.session;

  if (sessionCookie && sessionCookie.startsWith('secure_session_token_')) {
    res.json({
      user: {
        id: 'usr_001',
        email: 'user@example.com',
        role: 'user'
      }
    });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// ============================================
// CSRF Demo Endpoints
// ============================================

// Vulnerable transfer - no CSRF protection
server.post('/api/vulnerable/transfer', (req, res) => {
  const { recipient, amount } = req.body;

  // VULNERABLE: No CSRF token validation
  console.log('VULNERABLE: Transfer without CSRF check:', { recipient, amount });

  res.json({
    success: true,
    message: `Transferred $${amount} to ${recipient}`,
    warning: 'This endpoint has no CSRF protection!'
  });
});

// Vulnerable email update via GET
server.get('/api/vulnerable/update-email', (req, res) => {
  const { email } = req.query;

  // VULNERABLE: State change via GET request
  console.log('VULNERABLE: Email update via GET:', email);

  res.json({
    success: true,
    message: `Email updated to ${email}`,
    warning: 'GET should not be used for state changes!'
  });
});

// Secure transfer - with CSRF validation
server.post('/api/secure/transfer', (req, res) => {
  const { recipient, amount } = req.body;
  const xsrfHeader = req.headers['x-xsrf-token'];
  const xsrfCookie = req.cookies?.['XSRF-TOKEN'];

  // SECURE: Validate CSRF token
  if (!xsrfHeader || !xsrfCookie) {
    return res.status(403).json({ error: 'Missing CSRF token' });
  }

  // In real app, would validate token matches
  // For demo, just check they exist

  res.json({
    success: true,
    message: `Securely transferred $${amount} to ${recipient}`,
    csrfValidated: true
  });
});

// ============================================
// Comment Endpoints (XSS Demo)
// ============================================

// Get all comments
server.get('/api/comments', (req, res) => {
  const db = router.db.getState();
  res.json(db.comments);
});

// Add comment (for XSS demo)
server.post('/api/comments', (req, res) => {
  const { author, body } = req.body;
  const db = router.db.getState();

  const newComment = {
    id: 'cmt_' + Date.now(),
    author: author || 'Anonymous',
    body,
    date: new Date().toISOString().split('T')[0]
  };

  db.comments.push(newComment);
  res.json(newComment);
});

// ============================================
// Error handler
// ============================================

server.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// Use default router for other endpoints
// ============================================

server.use('/api', router);

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║           Angular Security Lab - Mock Server               ║
╠════════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:${PORT}                  ║
║                                                            ║
║  Endpoints:                                                ║
║  ─────────────────────────────────────────────────────────║
║  Vulnerable:                                               ║
║    POST /api/vulnerable/login      (logs credentials)      ║
║    POST /api/vulnerable/transfer   (no CSRF)               ║
║    GET  /api/vulnerable/update-email (GET state change)    ║
║                                                            ║
║  Secure:                                                   ║
║    POST /api/auth/login            (HttpOnly cookie)       ║
║    POST /api/auth/logout           (clears session)        ║
║    GET  /api/auth/session          (validates session)     ║
║    POST /api/secure/transfer       (CSRF protected)        ║
║                                                            ║
║  Data:                                                     ║
║    GET  /api/users                                         ║
║    GET  /api/comments                                      ║
║    POST /api/comments                                      ║
╚════════════════════════════════════════════════════════════╝
  `);
});
