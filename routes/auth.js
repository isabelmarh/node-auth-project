const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const User = require('../model/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config');
const  Refresh = require('../model/refresh');
const crypto = require('crypto');

/**
 * @method - POST
 * @param - /register
 * @description - User Sign Up
 */

router.post('/register',
    [
        body('name').isLength({ min: 3 }),
        body('email').isEmail(),
        body('password').custom((value, { req }) => {
            const regexPassword = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
            if (!regexPassword.test(value)) {
                throw new Error('Password must contain at least 8 characters and must have a letter and a number');
            }
            return true;
        }),
        body('passwordConfirmation').custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Password confirmation does not match password');
            }
            return true;
        }),
    ],
    async (req, res) => {
        try {
            // If there are no errors
            const { email } = req.body;
            const userExists = await User.findOne({ email });
            if (userExists) {
                return res.status(400).json({ error: 'User already exists' });
            }
            // Creating and saving the user 
            const user = await User.create(req.body);
            res.status(200).json({ user });

        } catch (error) {
            const errors = validationResult(req);
            // If there are errors ...
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
        }
    }
);

/**
 * @method - POST
 * @param - /login
 * @description - User Log In
 */

router.post('/login',
    [
        body('email').isEmail(),
        body('password').custom((value, { req }) => {
            const regexPassword = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
            if (!regexPassword.test(value)) {
                throw new Error('Password must contain at least 8 characters and must have a letter and a number');
            }
            return true;
        }),
        body('passwordConfirmation').custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Password confirmation does not match password');
            }
            return true;
        }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: errors.array()
            });
        }
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'No user with such email' });
        }
        //Compare passwords with bcrypt.compare method 
        //the first password parameter is the one in plain text, 
        //and the second user.password is the hashed password
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'The password is incorrect' });
        }
        //generate an access token
        const accessToken = jwt.sign(
            { _id: user._id, email: user.email },
            jwtSecret,
            { expiresIn: '1h' });
        res.header('authorization', accessToken).json({
            error: null,
            data: { accessToken }
        });
        const refreshToken = crypto.randomBytes(32).toString('hex');
        await Refresh.create({
            user: user._id,
            token: refreshToken
        });
        user.lastActive = Date.now();
        await user.save();
        res.status(200).json({ accessToken, refreshToken });
    }
);

module.exports = router;