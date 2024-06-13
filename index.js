const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const SECRET_KEY = 'your-secret-key'; // Replace with your own secret key

// Connection URL
const url = 'mongodb://localhost:27017/mriirs';
const client = new MongoClient(url);
// Database Name
const dbName = 'mriirs';

// Middleware to handle file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads/');
  },
  filename: function (req, file, cb) {
    const uniquePrefix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniquePrefix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Middleware to parse request bodies
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());


// Middleware to handle sessions
app.use(session({
  secret: 'your-session-secret', // Replace with your own session secret key
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 5 * 60 * 1000 } // Session expires in 5 minutes
}));

// Middleware to serve static files from the 'uploads' directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Home page
app.get('/', function (req, res) {
  res.sendFile(__dirname + '/templates/home.html');
});

// Handle complaint form submission
app.post('/', upload.single('uploaded_file'), async function (req, res) {
  const { user_name: name, user_email: email, user_location: location, user_message: message } = req.body;
  const img_path = req.file.path;

  console.log(req.file, req.body);

  try {
    await client.connect();
    console.log('Connected successfully to server');
    const db = client.db(dbName);
    const collection = db.collection('complaints');

    await collection.insertOne({ email, name, location, message, img_path });
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.status(500).send('Internal Server Error');
  } finally {
    await client.close();
  }
});

// Signup page
app.get('/signup', function (req, res) {
  res.sendFile(__dirname + '/templates/Signup.html');
});

app.post('/signup', async function (req, res) {
  const { user_name:UserName,user_email: email, user_pwd1: password1, user_pwd2: password2 } = req.body;

  console.log(email, password1, password2,UserName);

  if (password1 !== password2) {
    return res.send('Passwords do not match');
  }

  try {
    await client.connect();
    console.log('Connected successfully to server');
    const db = client.db(dbName);
    const collection = db.collection('user');

    const existingUser = await collection.findOne({ User_email: email });

    if (existingUser) {
      return res.send('Email already exists. Please use a different email.');
    }

    const hashedPassword = await bcrypt.hash(password1, saltRounds);
    await collection.insertOne({username:UserName,User_email: email, User_Password: hashedPassword });

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  } finally {
    await client.close();
  }
});

// Admin page to show all complaints
app.get('/admin', async function (req, res) {
  if (!req.session.loggedIn) {
    return res.redirect('/login');
  }

  try {
    await client.connect();
    console.log('Connected successfully to server');
    const db = client.db(dbName);
    const collection = db.collection('complaints');
    
    const complaints = await collection.find({}).toArray();
    
    // Read the template HTML file
    const template = fs.readFileSync(__dirname + '/templates/admin.html', 'utf8');
    
    // Generate HTML for complaints
    let complaintsHtml = complaints.map(complaint => `
      <div class="card">
        <h2>${complaint.name}</h2>
        <p><strong>Email:</strong> ${complaint.email}</p>
        <p><strong>Location:</strong> ${complaint.location}</p>
        <p><strong>Message:</strong> ${complaint.message}</p>
        ${complaint.img_path ? `<a href="/${complaint.img_path}" target="_blank">View Image</a>` : 'No image available'}
      </div>
    `).join('');
    
    // Inject complaints HTML into the template
    const html = template.replace('<!-- COMPLAINTS_PLACEHOLDER -->', complaintsHtml);
    
    // Send the response
    res.send(html);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  } finally {
    await client.close();
  }
});

// Rate limiter to prevent brute-force attacks
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: "Too many login attempts from this IP, please try again after 5 minutes"
});

// Login page
app.get('/login', function (req, res) {
  res.sendFile(__dirname + '/templates/Login.html');
});

// Handle login requests
app.post('/login', loginLimiter, async function (req, res) {
  const { user_email: email, user_pwd: password } = req.body;

  try {
    await client.connect();
    console.log('Connected successfully to server');
    const db = client.db(dbName);
    const collection = db.collection('user');

    const user = await collection.findOne({ User_email: email });

    if (!user) {
      return res.send('Invalid email or password.');
    }

    const match = await bcrypt.compare(password, user.User_Password);

    if (match) {
      req.session.loggedIn = true;
      req.session.user = user;

      // Generate a token
      const token = jwt.sign({ email: user.User_email }, SECRET_KEY, { expiresIn: '5m' });

      // Set the token as a cookie
      res.cookie('token', token, { httpOnly: true });

      return res.redirect('/admin');
    } else {
      return res.send('Invalid email or password.');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  } finally {
    await client.close();
  }
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
