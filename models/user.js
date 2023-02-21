const mongoose = require('mongoose');

const Schema = mongoose.Schema;

// create user schema
const UserSchema = new Schema({
    _id: {
        type: mongoose.Types.ObjectId,
    },
    name: {
        type: String,
        required: true
    },
    username: {
        type : String,
        required:true,
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    image: {
        type: String
    }
});

module.exports = User = mongoose.model('user', UserSchema , 'users');
