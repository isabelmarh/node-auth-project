const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config');

const verifyJWT = (req, res, next) => {
    try {
        // console.log(req.headers)
        const accessToken = req.headers.authorization;
        // console.log(accessToken, jwtSecret)
        const decoded = jwt.verify(accessToken, jwtSecret);
        req.userId = decoded._id;
        next();
    } catch (error) {
        res.status(403).json({ Error: 'Invalid token' });
    }
};
module.exports = verifyJWT;

