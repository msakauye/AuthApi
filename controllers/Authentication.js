const jwt = require('jwt-simple');
const User = require('../models/User');
const config = require('../config');

function tokenForUser(user) {
    const timestamp = new Date().getTime();
    // sub = subject, should be something that never changes
    // iat = issued at time
    return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
    // User has already had their email and password auth'd
    // just need to give them a token
    res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
    const email = req.body.email;
    const password = req.body.password;
    
    if (!email || !password) {
        return res.status(422).send({ error: 'You must provide email and password' });
    }

    // See if a user with given email exists
    User.findOne({ email: email }, function(err, existingUser) {
        if (err) {
            return next(err);
        }
        
        // If a user with email already exists, return error
        if (existingUser) {
            return res.status(422).send({ error: 'Email is in use' });
        }

        // If email is new, create and save user record
        const user = new User({
            email: email,
            password: password
        });
        user.save(function(err) {
            if (err) {
                return next(err);
            }

            // Respond to request
            res.json({ token: tokenForUser(user) });
        });
    });
}