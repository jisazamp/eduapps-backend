const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const app = express()

// Configure CORS
app.use(cors())

// Configure body parser to read JSON data
app.use(express.json())

// Connect to MongoDB database
mongoose.connect('mongodb://localhost:27017/auth', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

// Define user schema
const userSchema = new mongoose.Schema({
  email: String,
  firstName: String,
  lastName: String,
  password: String,
})

// Define user model
const User = mongoose.model('User', userSchema)

app.post('/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body

  if (!password) {
    return res.status(400).json({ message: 'Password is required' })
  }

  if (!email || !firstName || !lastName) {
    return res.status(400).json({ message: 'All fields are required' })
  }

  // Check if user already exists
  const existingUser = await User.findOne({ email: email.toLowerCase().trim() })
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' })
  }

  // Hash password
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  // Create new user
  const user = new User({
    email: email.toLowerCase().trim(),
    firstName,
    lastName,
    password: hashedPassword,
  })
  await user.save()

  res.status(201).json({ message: 'User registered successfully' })
})

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body

  // Find user by email
  const user = await User.findOne({ email: email.toLowerCase().trim() })
  if (!user) {
    return res.status(400).json({ message: 'Invalid email or password' })
  }

  // Check password
  const validPassword = await bcrypt.compare(password, user.password)
  if (!validPassword) {
    return res.status(400).json({ message: 'Invalid email or password' })
  }

  // Create and send JWT token
  const token = jwt.sign({ id: user._id }, 'secret-key')
  res.json({ token })
})

// Logout endpoint
app.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful' })
})

// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000')
})
