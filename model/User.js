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
        trim: true
    },
    hashedPassword: {
        type: String,
        required: [true, 'must provide password'],
        trim: true
    }
});

export default mongoose.model('User', UserSchema);