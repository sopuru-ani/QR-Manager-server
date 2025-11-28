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
    ip: {
        type: String,
        required: true,
    },
}, { timestamps: true });

export default mongoose.model("ScanLog", ScanLogSchema);
