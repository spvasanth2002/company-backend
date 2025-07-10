require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const serverless = require('serverless-http');

const app = express();
const router = express.Router();

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Handle trailing slashes
app.use((req, res, next) => {
  if (req.url.endsWith('/') && req.url !== '/') {
    req.url = req.url.slice(0, -1);
  }
  next();
});

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});
const User = mongoose.model('User', userSchema);

const isValidPassword = (password) => {
  return password.length >= 8 && /\d/.test(password);
};

router.post('/signup', async (req, res) => {
  console.log('Received POST request to /signup with body:', req.body);
  const { email, password } = req.body;
  if (!isValidPassword(password)) {
    return res.status(400).json({ message: 'Password must be at least 8 characters and contain a number.' });
  }
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists. Please log in.' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ email, password: hashedPassword });
  await newUser.save();
  res.json({ message: 'Signup successful. Please log in.' });
});

router.post('/login', async (req, res) => {
  console.log('Received POST request to /login with body:', req.body);
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Invalid email or password.' });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid email or password.' });
  res.json({ message: 'Login successful' });
});

router.post('/forgot-password', async (req, res) => {
  console.log('Received POST request to /forgot-password with body:', req.body);
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Email not found' });
  res.json({ message: 'Reset link sent to email (simulated).' });
});

router.get('/', (req, res) => {
  console.log('Received GET request to /');
  res.send('API is running.');
});

app.use('/.netlify/functions/api', router);
module.exports = app;
module.exports.handler = serverless(app);