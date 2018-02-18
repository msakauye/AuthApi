const Authentication = require('./controllers/Authentication');
const passportService = require('./services/passport');
const passport = require('passport');

// used to verify a valid jwt token in a request
const requireAuth = passport.authenticate('jwt', { session: false });

// used to verify a valid email/password credentials
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app) {
    // example on how to use requireAuth:
    app.get('/', requireAuth, function(req, res) {
        res.send({ message: 'Super secret code is ABC123' });
    })
    app.post('/signin', requireSignin, Authentication.signin);
    app.post('/signup', Authentication.signup);
}