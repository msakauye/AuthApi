const passport = require('passport');
const User = require('../models/User');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

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
