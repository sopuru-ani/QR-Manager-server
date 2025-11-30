import mongoose from "mongoose";

const VerifySchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'must provide email'],
        trim: true,
    },
    code: {
        type: String,
        required: [true]
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 600,
    }
});

export default mongoose.model('Verifies', VerifySchema);