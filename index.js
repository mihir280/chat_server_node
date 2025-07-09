require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const User = require('./models/User');
const Message = require('./models/Message');
const initGoogleAuth = require('./auth/google');

// Create express app
const app = express();
app.use(express.json());
app.use(cors());

// Health‑check endpoint
app.get('/', (req, res) => {
  res.send('Chat server is up and running 🚀');
});

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());
initGoogleAuth(); // Configure Google OAuth

// --- AUTH ROUTES ---

// Google OAuth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: true }),
  (req, res) => {
    // Issue a JWT
    const token = jwt.sign(
      { id: req.user._id, email: req.user.email },
      process.env.JWT_SECRET || 'jwtsecret',
      { expiresIn: '7d' }
    );
    // Redirect back to the app via custom URI scheme
    const redirectUrl = `myapp://auth`
      + `?token=${token}`
      + `&id=${req.user._id}`
      + `&name=${encodeURIComponent(req.user.name)}`
      + `&email=${encodeURIComponent(req.user.email)}`
      + `&avatar=${encodeURIComponent(req.user.avatar || '')}`;
    res.redirect(redirectUrl);
  }
);

// Logout
app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Get current user
app.get('/auth/current_user', (req, res) => {
  res.json(req.user || null);
});

// JWT verification middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET || 'jwtsecret', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    req.user = user;
    next();
  });
}

// Update profile
app.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { name, avatar } = req.body;
    const update = {};
    if (name) update.name = name;
    if (avatar) update.avatar = avatar;
    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ id: user._id, name: user.name, email: user.email, avatar: user.avatar });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// List all users
app.get('/users', async (req, res) => {
  try {
    const users = await User.find({}, 'name email avatar');
    // Map _id to id for each user
    const usersWithId = users.map(u => ({
      id: u._id,
      name: u.name,
      email: u.email,
      avatar: u.avatar || ''
    }));
    res.json(usersWithId);
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// Signup
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'User already exists.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword });
    res.status(201).json({ message: 'User created successfully.' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const user = await User.findOne({ email });
    if (!user || !user.password) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials.' });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || 'jwtsecret',
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// Create a message
app.post('/messages', authenticateToken, async (req, res) => {
  try {
    const { receiver, content } = req.body;
    if (!receiver || !content) {
      return res.status(400).json({ message: 'Receiver and content are required.' });
    }
    const message = await Message.create({
      sender: req.user.id,
      receiver,
      content,
    });
    res.status(201).json(message);
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// Get message history
app.get('/messages', authenticateToken, async (req, res) => {
  try {
    const { user1, user2 } = req.query;
    if (!user1 || !user2) {
      return res.status(400).json({ message: 'user1 and user2 are required.' });
    }
    const messages = await Message.find({
      $or: [
        { sender: user1, receiver: user2 },
        { sender: user2, receiver: user1 },
      ],
    }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// --- SOCKET.IO SETUP ---

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});

// In‑memory maps
let userSocketMap = {};

io.on('connection', (socket) => {
  const userId = socket.handshake.query.userId;
  if (userId) {
    userSocketMap[userId] = socket.id;
    console.log(`User ${userId} connected as socket ${socket.id}`);
  }

  socket.on('send_message', async (data) => {
    const message = {
      sender: userId,
      receiver: data.receiver,
      content: data.content,
      timestamp: new Date(),
    };
    await Message.create(message);

    const receiverSocket = userSocketMap[data.receiver];
    if (receiverSocket) {
      io.to(receiverSocket).emit('receive_message', message);
    }
    socket.emit('receive_message', message);
  });

  socket.on('disconnect', () => {
    if (userId) delete userSocketMap[userId];
    console.log(`User disconnected: ${socket.id}`);
  });
});

// --- DATABASE CONNECTION & SERVER LISTEN ---

mongoose
  .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/chatverse')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
