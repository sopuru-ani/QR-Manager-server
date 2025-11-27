import mongoose from "mongoose";

function connectDB(url) {
    return mongoose.connect(url);
}

export default connectDB;