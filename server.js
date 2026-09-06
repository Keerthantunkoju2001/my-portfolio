require('dotenv').config();

console.log("SMTP HOST:", process.env.SMTP_HOST);
console.log("SMTP USER:", process.env.SMTP_USER);
console.log("SMTP PASS SET:", !!process.env.SMTP_PASS);
console.log("CONTACT EMAIL:", process.env.CONTACT_TO_EMAIL);
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

const PORTFOLIO_FILE = path.join(DATA_DIR, 'portfolio.json');
const SEED_FILE = path.join(DATA_DIR, 'portfolio.seed.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const CONTACTS_FILE = path.join(DATA_DIR, 'contacts.json');
const SECRET_FILE = path.join(DATA_DIR, '.jwt-secret');

for (const dir of [DATA_DIR, UPLOADS_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// ---------- JSON FILE HELPERS ----------

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return fallback;
  }
}

function writeJsonAtomic(file, data) {
  const tmp = file + '.tmp';

  fs.writeFileSync(
    tmp,
    JSON.stringify(data, null, 2)
  );

  fs.renameSync(tmp, file);
}

// ---------- INITIAL FILES ----------

if (!fs.existsSync(PORTFOLIO_FILE)) {
  const seed = readJson(SEED_FILE, {});
  writeJsonAtomic(PORTFOLIO_FILE, seed);
}

if (!fs.existsSync(AUTH_FILE)) {
  writeJsonAtomic(AUTH_FILE, {
    passwordHash: null
  });
}

if (!fs.existsSync(CONTACTS_FILE)) {
  writeJsonAtomic(CONTACTS_FILE, []);
}

// ---------- JWT SECRET ----------

let JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  if (fs.existsSync(SECRET_FILE)) {
    JWT_SECRET = fs.readFileSync(
      SECRET_FILE,
      'utf8'
    ).trim();
  } else {
    JWT_SECRET = crypto.randomBytes(48).toString('hex');

    fs.writeFileSync(
      SECRET_FILE,
      JWT_SECRET
    );
  }
}

// ---------- APP SETUP ----------

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: {
      policy: 'cross-origin'
    }
  })
);

app.use(cors());

app.use(
  express.json({
    limit: '2mb'
  })
);

const PORT = process.env.PORT || 4000;

// ---------- RATE LIMITING ----------

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    error: 'Too many attempts. Please try again later.'
  }
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    error: 'Too many messages sent. Please try again later.'
  }
});

// ---------- AUTH HELPERS ----------

function signToken() {
  return jwt.sign(
    {
      role: 'admin'
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

function requireAuth(req, res, next) {
  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : null;

  if (!token) {
    return res.status(401).json({
      error: 'Missing authorization token.'
    });
  }

  try {
    req.admin = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch (e) {
    return res.status(401).json({
      error:
        'Invalid or expired session. Please log in again.'
    });
  }
}

// ---------- AUTH ROUTES ----------

app.get('/api/auth/status', (req, res) => {
  const auth = readJson(
    AUTH_FILE,
    {
      passwordHash: null
    }
  );

  res.json({
    passwordSet: !!auth.passwordHash
  });
});

app.post(
  '/api/auth/setup',
  loginLimiter,
  async (req, res) => {

    const auth = readJson(
      AUTH_FILE,
      {
        passwordHash: null
      }
    );

    if (auth.passwordHash) {
      return res.status(409).json({
        error:
          'A password is already set. Use login instead.'
      });
    }

    const {
      password
    } = req.body || {};

    if (
      !password ||
      String(password).length < 6
    ) {
      return res.status(400).json({
        error:
          'Password must be at least 6 characters.'
      });
    }

    const hash = await bcrypt.hash(
      String(password),
      12
    );

    writeJsonAtomic(
      AUTH_FILE,
      {
        passwordHash: hash
      }
    );

    res.json({
      token: signToken()
    });
  }
);

app.post(
  '/api/auth/login',
  loginLimiter,
  async (req, res) => {

    const auth = readJson(
      AUTH_FILE,
      {
        passwordHash: null
      }
    );

    if (!auth.passwordHash) {
      return res.status(409).json({
        error:
          'No password set yet. Please complete setup first.'
      });
    }

    const {
      password
    } = req.body || {};

    const ok =
      password &&
      await bcrypt.compare(
        String(password),
        auth.passwordHash
      );

    if (!ok) {
      return res.status(401).json({
        error: 'Incorrect password.'
      });
    }

    res.json({
      token: signToken()
    });
  }
);

app.post(
  '/api/auth/change-password',
  requireAuth,
  async (req, res) => {

    const auth = readJson(
      AUTH_FILE,
      {
        passwordHash: null
      }
    );

    const {
      oldPassword,
      newPassword
    } = req.body || {};

    const ok =
      oldPassword &&
      auth.passwordHash &&
      await bcrypt.compare(
        String(oldPassword),
        auth.passwordHash
      );

    if (!ok) {
      return res.status(401).json({
        error:
          'Current password is incorrect.'
      });
    }

    if (
      !newPassword ||
      String(newPassword).length < 6
    ) {
      return res.status(400).json({
        error:
          'New password must be at least 6 characters.'
      });
    }

    const hash = await bcrypt.hash(
      String(newPassword),
      12
    );

    writeJsonAtomic(
      AUTH_FILE,
      {
        passwordHash: hash
      }
    );

    res.json({
      ok: true
    });
  }
);

// ---------- PORTFOLIO ROUTES ----------

app.get('/api/portfolio', (req, res) => {
  res.json(
    readJson(
      PORTFOLIO_FILE,
      {}
    )
  );
});

app.put(
  '/api/portfolio',
  requireAuth,
  (req, res) => {

    const body = req.body;

    if (
      !body ||
      typeof body !== 'object' ||
      Array.isArray(body)
    ) {
      return res.status(400).json({
        error:
          'Request body must be a portfolio object.'
      });
    }

    writeJsonAtomic(
      PORTFOLIO_FILE,
      body
    );

    res.json({
      ok: true,
      savedAt: new Date().toISOString()
    });
  }
);

// ---------- UPLOADS ----------

const ALLOWED_IMAGE = [
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif'
];

const ALLOWED_DOC = [
  'application/pdf'
];

const storage =
  multer.diskStorage({

    destination: (
      req,
      file,
      cb
    ) => {
      cb(
        null,
        UPLOADS_DIR
      );
    },

    filename: (
      req,
      file,
      cb
    ) => {

      const safeExt =
        path.extname(
          file.originalname
        )
        .toLowerCase()
        .replace(
          /[^a-z0-9.]/g,
          ''
        );

      cb(
        null,
        `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${safeExt}`
      );
    }
  });

const upload =
  multer({

    storage,

    limits: {
      fileSize:
        8 * 1024 * 1024
    },

    fileFilter: (
      req,
      file,
      cb
    ) => {

      if (
        ALLOWED_IMAGE.includes(
          file.mimetype
        ) ||
        ALLOWED_DOC.includes(
          file.mimetype
        )
      ) {
        cb(null, true);
      } else {
        cb(
          new Error(
            'Unsupported file type. Please upload a JPG, PNG, WEBP, GIF, or PDF.'
          )
        );
      }
    }
  });

app.post(
  '/api/upload',
  requireAuth,
  (req, res) => {

    upload.single('file')(
      req,
      res,
      (err) => {

        if (err) {
          return res.status(400).json({
            error: err.message
          });
        }

        if (!req.file) {
          return res.status(400).json({
            error:
              'No file received.'
          });
        }

        res.json({
          url:
            `/uploads/${req.file.filename}`,

          filename:
            req.file.originalname
        });
      }
    );
  }
);

app.use(
  '/uploads',
  express.static(
    UPLOADS_DIR,
    {
      maxAge: '7d'
    }
  )
);

// ---------- CONTACT ----------

function isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    String(v || '')
  );
}

function escapeHtml(value) {
  return String(value || '')
    .replace(
      /&/g,
      '&amp;'
    )
    .replace(
      /</g,
      '&lt;'
    )
    .replace(
      />/g,
      '&gt;'
    )
    .replace(
      /"/g,
      '&quot;'
    )
    .replace(
      /'/g,
      '&#039;'
    );
}

// ---------- CONTACT FORM ----------

app.post(
  '/api/contact',
  contactLimiter,
  async (req, res) => {

    console.log(
      '📩 CONTACT API CALLED'
    );

    console.log(
      'Received data:',
      req.body
    );

    const {
      name,
      email,
      message
    } = req.body || {};

    // Validate name
    if (
      !name ||
      !String(name).trim()
    ) {
      return res.status(400).json({
        error:
          'Name is required.'
      });
    }

    // Validate email
    if (!isValidEmail(email)) {
      return res.status(400).json({
        error:
          'A valid email is required.'
      });
    }

    // Validate message
    if (
      !message ||
      !String(message).trim()
    ) {
      return res.status(400).json({
        error:
          'Message is required.'
      });
    }

    // Create contact entry
    const entry = {
      id: crypto.randomUUID(),

      name:
        String(name)
          .trim()
          .slice(0, 200),

      email:
        String(email)
          .trim()
          .slice(0, 200),

      message:
        String(message)
          .trim()
          .slice(0, 5000),

      receivedAt:
        new Date().toISOString(),

      read: false
    };

    // Save message
    const contacts =
      readJson(
        CONTACTS_FILE,
        []
      );

    contacts.unshift(entry);

    writeJsonAtomic(
      CONTACTS_FILE,
      contacts
    );

    console.log(
      '✅ Contact message saved.'
    );

    // ---------- SEND EMAIL ----------

    const smtpConfigured =
      process.env.SMTP_HOST &&
      process.env.SMTP_USER &&
      process.env.SMTP_PASS &&
      process.env.CONTACT_TO_EMAIL;

    if (!smtpConfigured) {

      console.error(
        '❌ SMTP is not configured.'
      );

      return res.status(503).json({
        error:
          'Message was saved, but email notifications are not configured on the server.',

        saved: true,

        emailSent: false
      });
    }

    try {

      const nodemailer =
        require('nodemailer');

      const smtpPort =
        Number(
          process.env.SMTP_PORT || 465
        );

      const transporter =
        nodemailer.createTransport({

          host:
            process.env.SMTP_HOST,

          port:
            smtpPort,

          secure:
            smtpPort === 465,

          auth: {
            user:
              process.env.SMTP_USER,

            pass:
              process.env.SMTP_PASS
          }
        });

      await transporter.sendMail({

        from:
          `"Portfolio Contact Form" <${process.env.SMTP_USER}>`,

        to:
          process.env.CONTACT_TO_EMAIL,

        replyTo:
          entry.email,

        subject:
          `New portfolio message from ${entry.name}`,

        text:
`You received a new message from your portfolio.

Name: ${entry.name}
Email: ${entry.email}

Message:
${entry.message}

Received: ${entry.receivedAt}`,

        html:
`
<div style="font-family:Arial,sans-serif;line-height:1.6;max-width:650px">

  <h2>New Portfolio Contact Message</h2>

  <p>
    <strong>Name:</strong>
    ${escapeHtml(entry.name)}
  </p>

  <p>
    <strong>Email:</strong>
    ${escapeHtml(entry.email)}
  </p>

  <p>
    <strong>Message:</strong>
  </p>

  <div
    style="
      padding:15px;
      background:#f5f5f5;
      border-radius:8px;
      white-space:pre-wrap;
    "
  >
    ${escapeHtml(entry.message)}
  </div>

  <p style="color:#777;font-size:12px">
    Received:
    ${escapeHtml(entry.receivedAt)}
  </p>

</div>
`
      });

      console.log(
        `📧 Email sent successfully to ${process.env.CONTACT_TO_EMAIL}`
      );

      return res.json({

        ok: true,

        saved: true,

        emailSent: true
      });

    } catch (e) {

      console.error(
        '❌ Email notification failed:',
        e.message
      );

      return res.status(502).json({

        error:
          'Message was saved, but the email notification could not be sent. Check your SMTP settings.',

        saved: true,

        emailSent: false
      });
    }
  }
);

// ---------- ADMIN CONTACT MESSAGES ----------

app.get(
  '/api/contact',
  requireAuth,
  (req, res) => {

    res.json(
      readJson(
        CONTACTS_FILE,
        []
      )
    );
  }
);

app.patch(
  '/api/contact/:id/read',
  requireAuth,
  (req, res) => {

    const contacts =
      readJson(
        CONTACTS_FILE,
        []
      );

    const entry =
      contacts.find(
        c =>
          c.id ===
          req.params.id
      );

    if (!entry) {
      return res.status(404).json({
        error:
          'Message not found.'
      });
    }

    entry.read = true;

    writeJsonAtomic(
      CONTACTS_FILE,
      contacts
    );

    res.json({
      ok: true
    });
  }
);

app.delete(
  '/api/contact/:id',
  requireAuth,
  (req, res) => {

    const contacts =
      readJson(
        CONTACTS_FILE,
        []
      );

    const next =
      contacts.filter(
        c =>
          c.id !==
          req.params.id
      );

    writeJsonAtomic(
      CONTACTS_FILE,
      next
    );

    res.json({
      ok: true
    });
  }
);

// ---------- STATIC FRONTEND ----------

const PUBLIC_DIR =
  path.join(
    __dirname,
    'public'
  );

app.use(
  express.static(
    PUBLIC_DIR
  )
);

app.get(
  '/',
  (req, res) => {

    res.sendFile(
      path.join(
        PUBLIC_DIR,
        'index.html'
      )
    );
  }
);

// ---------- HEALTH CHECK ----------

app.get(
  '/api/health',
  (req, res) => {

    res.json({
      ok: true,
      time:
        new Date().toISOString()
    });
  }
);

// ---------- ERROR HANDLER ----------

app.use(
  (err, req, res, next) => {

    console.error(err);

    res.status(500).json({
      error:
        'Something went wrong on the server.'
    });
  }
);

// ---------- START SERVER ----------

app.listen(
  PORT,
  () => {

    console.log(
      `Portfolio server running at http://localhost:${PORT}`
    );
  }
);