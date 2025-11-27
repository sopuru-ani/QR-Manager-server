import mongoose from "mongoose";

const QRcodeSchema = new mongoose.Schema({
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'must provide user'],
    },
    url: {
        type: String,
        required: [true, 'must provide url'],
    },
    title: {
        type: String,
        required: [true, 'must provide title to identify QR code'],
        trim: true
    },
    clicks: {
        type: Number,
        default: 0
    },
    dateCreated: {
        type: Date,
        default: Date.now
    },
    dateModified: {
        type: Date,
        default: Date.now
    }
});

export default mongoose.model('QRCode', QRcodeSchema);