import mongoose from "mongoose";

const ScanLogSchema = new mongoose.Schema({
    qrId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "QRCode",
        required: true,
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
    },
    timestamp: {
        type: Date,
        default: Date.now,
    },
});

export default mongoose.model("ScanLog", ScanLogSchema);