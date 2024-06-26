const jwt = require('jsonwebtoken');
const { hashPassword, comparePassword } = require('../utils/hash');
const User = require('../models/user');

const register = async (req, res) => {
  const { first_name, last_name, email, age, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'Email already taken' });
  }

  const hashedPassword = await hashPassword(password);
  const newUser = await User.create({ first_name, last_name, email, age, password: hashedPassword });
  return res.status(201).json({ message: 'User created', user: newUser });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await comparePassword(password, user.password))) {
    return res.status(400).json({ message: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.cookie('jwt', token, { httpOnly: true, secure: true });
  res.status(200).json({ message: 'Logged in successfully', token });
};

const logout = (req, res) => {
  res.clearCookie('jwt');
  res.status(200).json({ message: 'Logged out successfully' });
};

const current = async (req, res) => {
  const token = req.cookies.jwt;
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    res.status(200).json({ user });
  } catch (err) {
    res.status(401).json({ message: 'Unauthorized' });
  }
};

module.exports = { register, login, logout, current };