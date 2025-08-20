// server.js — auth-only (signup/login) on http://localhost:4000
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import User from './models/User.js';

dotenv.config();

const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(cors({ origin: (o, cb) => cb(null, true) }));

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/profai';
const PORT = process.env.PORT || 4000;

// health
app.get('/healthz', (_, res) => res.status(200).send('ok'));

// signup
app.post('/api/signup', async (req, res) => {
  try {
    let { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ message: 'Username and password required.' });

    username = String(username).trim().toLowerCase();
    if (username.length < 3) return res.status(400).json({ message: 'Username too short.' });
    if (String(password).length < 6) return res.status(400).json({ message: 'Password too short.' });

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ message: 'Username already taken.' });

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ username, passwordHash });

    return res.status(201).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    let { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ message: 'Username and password required.' });

    username = String(username).trim().toLowerCase();
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials.' });

    return res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: 'Server error' });
  }
});

async function start() {
  await mongoose.connect(MONGODB_URI);
  console.log('MongoDB connected');
  app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));
}
start();