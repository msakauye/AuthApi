const User = require('../models/User');

exports.signup = function(req, res, next) {
    const email = req.body.email;
    const password = req.body.password;
    console.log('req:', req.body);

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
            res.json({ success: true });
        });
    });
}