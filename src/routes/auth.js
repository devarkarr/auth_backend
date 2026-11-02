import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function signToken(user) {
  return jwt.sign({ sub: String(user.id), username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
}

function publicUser(user) {
  return { id: user.id, username: user.username, email: user.email, createdAt: user.created_at };
}

// POST /api/auth/register  { username, email, password }
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body ?? {};

  if (typeof username !== 'string' || username.trim().length < 3) {
    return res.status(400).json({ error: 'username must be at least 3 characters' });
  }
  if (typeof email !== 'string' || !EMAIL_RE.test(email.trim())) {
    return res.status(400).json({ error: 'email is invalid' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'password must be at least 6 characters' });
  }

  const existing = db
    .prepare('SELECT id FROM users WHERE username = ? OR email = ?')
    .get(username.trim(), email.trim());
  if (existing) {
    return res.status(409).json({ error: 'username or email already in use' });
  }

  const hash = await bcrypt.hash(password, 10);
  const { lastInsertRowid } = db
    .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
    .run(username.trim(), email.trim().toLowerCase(), hash);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(lastInsertRowid);
  res.status(201).json({ token: signToken(user), user: publicUser(user) });
});

// POST /api/auth/login  { email | username, password }
router.post('/login', async (req, res) => {
  const { email, username, password } = req.body ?? {};
  const identifier = (email ?? username ?? '').toString().trim();

  if (!identifier || typeof password !== 'string') {
    return res.status(400).json({ error: 'email (or username) and password are required' });
  }

  const user = db
    .prepare('SELECT * FROM users WHERE email = ? OR username = ?')
    .get(identifier, identifier);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ token: signToken(user), user: publicUser(user) });
});

// GET /api/auth/me  (Authorization: Bearer <token>)
router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: publicUser(user) });
});

// Wrong HTTP method on a known route (e.g. opening /register in a browser)
router.all(['/register', '/login'], (req, res) => {
  res.set('Allow', 'POST').status(405).json({ error: `Use POST for ${req.baseUrl}${req.path}` });
});
router.all('/me', (req, res) => {
  res.set('Allow', 'GET').status(405).json({ error: `Use GET for ${req.baseUrl}${req.path}` });
});

export default router;
