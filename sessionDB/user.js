const mongoose = require('mongoose');
const findOrCreate = require('mongoose-findorcreate');
require("mongoose-type-email");
const passportLocalMongoose = require('passport-local-mongoose');

const UserSchema = new mongoose.Schema({
    googleId:{
        type: String,
        required: true
    },
    displayName: {
        type: String,
        required: true
    },
    createdAt: {
        type:Date,
        default: Date.now
    }
});

UserSchema.plugin(passportLocalMongoose);
UserSchema.plugin(findOrCreate);
module.exports = mongoose.model('User',UserSchema);