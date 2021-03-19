var express = require('express');
var router = express.Router();
const User = require('../model/User');
const verifyJWT = require('../middleware/verifyToken');

//get info about each user in a private route
/* GET users listing. */
router.get('/userInfo', verifyJWT, async (req, res) => {
  try {
    let userInfo = await User.findById(req.userId);
    res.status(200).json(userInfo);
  } catch (error) {
    throw error;
  }
});

module.exports = router;


