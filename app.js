const jwt = require('jsonwebtoken');
const express = require('express');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

const secretKey = '';

app.post('/login', (req, res) => {
  // Assume user authentication and validation
    const user = {
        username: req.body.username,
        password: req.body.password
    }

  if (user) {
    const token = jwt.sign({ user }, secretKey, { expiresIn: '1h' })
    
    // Set the token as a cookie
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // 1 hour expiry

    res.json({ message: 'Login successful!' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/protected', authenticateToken, (req, res) => {
  // Access user via req.user
  res.json({ message: 'You are logged in!', user: req.user });
});

function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post('/logout', (req, res) => {
  // Clear the token cookie on the client-side
  res.clearCookie('token');
  res.json({ message: 'Logout successful!' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});