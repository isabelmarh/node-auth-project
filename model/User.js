const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');
const saltRounds = 10;

const userSchema = new Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    lastActive: {
        type: Date,
        default: Date.now()
    }
});

userSchema.pre('save', async function () {
    try {
        const user = this;

        if (user.isModified('password')) {
            user.password = await bcrypt.hash(user.password, saltRounds);
        }
    } catch (error) {
        throw error;
    }
});

module.exports = mongoose.model('User', userSchema);

