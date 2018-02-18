const passport = require('passport');
const User = require('../models/User');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local strategy
// Tell where to look in our request body for our username and password fields
// by default assumes 'username' and 'password'
const localOptions = {
    usernameField: 'email' // look at 'email' field for our username
    // passwordField: 'pass' // can also define another field for our password
}
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
    // verify this username and password
    // if valid credentials, call done with the user
    // else, call done with false
    User.findOne({ email: email }, function(err, user) {
        if (err) { return done(err); }

        if (!user) { return done(null, false); }

        // compare passwords - is `password` === user.password?
        // comparePassword is a function we defined on the User model in /models/User.js
        user.comparePassword(password, function(err, isMatch) {
            if (err) { return done(err); }
            if (!isMatch) { return done(null, false); }

            return done(null, user);
        });
    });
});

// Setup options for JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    // payload == decoded JWT token: { sub: user.id, iat: timestamp }
    // done == callback with signature function(error, user)
    
    // See if user ID in payload exists in DB
    // if yes, call done with that user
    // else, call done with false
    User.findById(payload.sub, function(err, user) {
        if (err) { return done(err, false); }

        // could also check timestamp to see if token is expired
        if (user) {
            done(null, user);
        } else {
            done(null, false);
        }
    })
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
