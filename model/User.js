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
    },
    avatar: {
        type: String,
        required: false,
    },
    googleId: {
        type: String,
        required: false,
    },
    googleAuth: {
        type: Boolean,
        default: false
    },
    resetToken: String,
    resetTokenExpires: Date
});

export default mongoose.model('User', UserSchema);
