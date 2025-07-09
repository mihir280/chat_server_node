require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');
const session = require('express-session');
const passport = require('passport');
const mongoose = require('mongoose');
const User = require('./models/User');
const initGoogleAuth = require('./auth/google');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Message = require('./models/Message');

// Create express app and server
const app = express();
app.use(express.json());
const server = http.createServer(app);

// Allow Flutter frontend to connect
app.use(cors());

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Initialize Google OAuth
initGoogleAuth();

// Google OAuth routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: true }),
  (req, res) => {
    // Create a JWT for the user
    const token = jwt.sign({ id: req.user._id, email: req.user.email }, process.env.JWT_SECRET || 'jwtsecret', { expiresIn: '7d' });
    // Redirect to your app with token and user info
    const redirectUrl = `myapp://auth?token=${token}&id=${req.user._id}&name=${encodeURIComponent(req.user.name)}&email=${encodeURIComponent(req.user.email)}&avatar=${encodeURIComponent(req.user.avatar || '')}`;
    res.redirect(redirectUrl);
  }
);

// Logout route
app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Get current user
app.get('/auth/current_user', (req, res) => {
  res.json(req.user || null);
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided.' });
  jwt.verify(token, process.env.JWT_SECRET || 'jwtsecret', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    req.user = user;
    next();
  });
}

// Update profile endpoint
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

// Get all users (for Home screen)
app.get('/users', async (req, res) => {
  try {
    const users = await User.find({}, 'name email avatar');
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// Signup endpoint
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
    const user = await User.create({ name, email, password: hashedPassword });
    res.status(201).json({ message: 'User created successfully.' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Login endpoint
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
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    // Create JWT token
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET || 'jwtsecret', { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// Send a message
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

// Get chat history between two users
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

// Start socket.io server
const io = new Server(server, {
  cors: {
    origin: '*',  // Allow all origins (for dev only)
    methods: ['GET', 'POST'],
  },
});

// Store connected users (in-memory)
let users = {};
let userSocketMap = {};

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/chatverse', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected');
  console.log('Connecting to MongoDB:', process.env.MONGO_URI);
}).catch((err) => {
  console.error('MongoDB connection error:', err);
});

io.on('connection', (socket) => {
  // Get userId from query
  const userId = socket.handshake.query.userId;
  if (userId) {
    userSocketMap[userId] = socket.id;
    console.log(`User ${userId} connected with socket ${socket.id}`);
  }

  // Handle real-time message
  socket.on('send_message', async (data) => {
    // data: { receiver, content }
    const message = {
      sender: userId,
      receiver: data.receiver,
      content: data.content,
      timestamp: new Date(),
    };
    // Save to DB
    await Message.create(message);

    // Emit to receiver if online
    const receiverSocketId = userSocketMap[data.receiver];
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('receive_message', message);
    }
    // Emit to sender for instant feedback
    socket.emit('receive_message', message);
  });

  socket.on('disconnect', () => {
    if (userId) {
      delete userSocketMap[userId];
    }
    console.log('User disconnected:', socket.id);
  });
});

// Start server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(` Server running on http://localhost:${PORT}`);
});
