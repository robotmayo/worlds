const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const passport = require('passport');
const passportLocal = require('passport-local');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const nconf = require('nconf');

const db = require('./db');
const patch = require('./patch-pgSession');



const LocalStrategy = passportLocal.Strategy;
const registerSchema = joi.object({
  username: joi.string().min(4).max(16).alphanum().required(),
  password: joi.string().min(8).max(64).required(),
  email: joi.string().required().max(256).email()
});

function localStrategyHandler(email, password, done) {
  db.query('SELECT id AS userid, password AS hash FROM user_accounts WHERE email = $1', [email])
    .then(({rows}) => {
      if (rows.length === 0) return done(null, false, {msg: 'User not found'});
      const {userid, hash} = rows[0];
      const valid = bcrypt.compareSync(password, hash);
      if (!valid) return done(null, false, {msg: 'Invalid password'});
      done(null, { userID: userid, email });
    })
    .catch(done);
}

function register({username, password, email}) {
  const hash = bcrypt.hashSync(password);
  return db.query('INSERT INTO user_accounts (username, password, email) VALUES ($1, $2, $3)', [username, hash, email]);
}

function postRegister(req, res) {
  const userData = { username: req.body.username, password: req.body.password, email: req.body.email };
  const result = registerSchema.validate(userData);
  if (result.error) {
    return res.json(result.error);
  }
  return register(userData)
    .then(results => {
      res.send('OK');
    })
    .catch(err => {
      res.json(err);
    })
}

function init(app) {
  app.use(session({
    store: patch(db, new pgSession({ pg: db, tableName: 'app_sessions' })),
    secret: nconf.get('cookie:secret'),
    resave: false,
    saveUninitialized: false
  }));
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(new LocalStrategy({ usernameField: 'email' }, localStrategyHandler));

  passport.serializeUser(function (user, done) {
    done(null, user);
  });

  passport.deserializeUser(function (user, done) {
    if (typeof user === 'object') return done(null, user);
    db.query('SELECT id as userID, email FROM user_accounts WHERE id = $1', [user.id])
      .then(({rows}) => {
        if (rows.length === 0) return done(new Error('Unable to find user'));
        done(null, rows[0]);
      })
      .catch(done);
  });
  app.get('/login', function login(req, res) {
    res.render('login');
  });
  app.post('/register', postRegister);
  app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' }));

}
module.exports.init = init;
