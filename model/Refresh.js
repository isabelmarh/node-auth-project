const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const refreshSchema = new Schema({
    user: {
        type: Schema.Types.ObjectId,
        required: true,
    },
    token: {
        type: String,
        expires: '180d',
    },
});

module.exports = mongoose.model('Refresh', refreshSchema);