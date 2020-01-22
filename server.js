if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const app = express();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const mongoose = require('mongoose');
const userSchema = require('./userSchema.js');
const User = mongoose.model('user', userSchema, 'user');

const initializePassport = require('./passport-config');
initializePassport(
  passport,
  async email => {
    const user = await User.findOne({ email: email });
    return user;
  },
  async id => {
    const user = await User.findOne({ _id: id });
    return user;
  }
);

app.set('view-engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.username });
});

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

app.post(
  '/login',
  checkNotAuthenticated,
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  })
);

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.name,
      email: req.body.email,
      password: hashedPassword
    });

    try {
      await user.save();
    } catch (err) {
      throw err;
    }

    res.redirect('/login');
  } catch {
    res.redirect('/register');
  }
});

app.post('/logout', (req, res) => {
  req.logOut();
  res.redirect('/login');
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
