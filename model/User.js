import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: [true, 'must provide first name'],
        trim: true
    },
    lastName: {
        type: String,
        required: [true, 'must provide last name'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'must provide email'],
        trim: true,
        unique: true
    },
    hashedPassword: {
        type: String,
        required: false,
        trim: true,
        default: ''
    },
    avatar: {
        type: String,
        required: false,
        default: ''
    },
    googleId: {
        type: String,
        required: false,
        default: ''
    },
    googleAuth: {
        type: Boolean,
        default: false
    }
});

export default mongoose.model('User', UserSchema);
