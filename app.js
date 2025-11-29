import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import QRcode from 'qrcode';
import mongoose from 'mongoose';
import { OAuth2Client } from 'google-auth-library';

import connectDB from './db/connect.js';
import User from './model/User.js';
import QRCode from './model/QRcodes.js';
import ScanLog from './model/ScanLogs.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET;
const exp = process.env.JWT_LIMIT;
const BASE_URL = "https://qr-manager-server-gec1.onrender.com";



// Middleware
const corsOptions = {
  origin: "https://qr-manager-beige.vercel.app",
  credentials: true,  // important for cookies
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());


function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (err) {
        return false;
    }
}
// Sample route
app.get('/', (req, res) => {
    return res.status(200).json({ msg: 'Welcome to the QR Code Generator API' });
});

app.get('/profile', async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        const profile = await User.find({ _id: userId }).select('firstName lastName email');
        return res.status(200).json(profile);
    } catch (error) {
        return res.status(500).json({ msg: 'Unauthorized' })
    }
});
//Login and signup routes would go here
app.post('/signup', async (req, res) => {
    if (!req.body) {
        return res.status(400).json({ msg: 'No data provided' });
    }
    const { firstName, lastName, email, password, confirmPassword } = req.body;
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
        return res.status(400).json({ msg: 'Please populate all fields' });
    }
    const user = await User.findOne({ email: email });
    if (user) {
        return res.status(400).json({ msg: 'Email already in use' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ msg: 'Passwords do not match' });
    }
    try {
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({
            firstName: firstName,
            lastName: lastName,
            email: email,
            hashedPassword: hashedPassword
        });
        await newUser.save();
        const token = jwt.sign({ userId: newUser._id }, secretKey, { expiresIn: exp });

       res.cookie('token', token, {
          httpOnly: true,
          secure: true,      // Required when using HTTPS domains
          sameSite: 'none'   // Required for cross-site cookies
        });
        return res.status(201).json({ msg: 'Account created successfully. redirecting...' });
    } catch (error) {
        return res.status(500).json({ msg: "Server Error. try again later" });
    }
});

app.post('/login', async (req, res) => {
    if (!req.body) {
        return res.status(400).json({ msg: 'No data provided' });
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status(400).json({ msg: 'Invalid email or password' });
    }
    try {
        if (await bcrypt.compare(password, user.hashedPassword)) {
            const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: exp });
            res.cookie('token', token, {
              httpOnly: true,
              secure: true,      // Required when using HTTPS domains
              sameSite: 'none'   // Required for cross-site cookies
            });
            return res.status(200).json({ msg: 'Login successful. redirecting...' });
        } else {
            return res.status(400).json({ msg: 'Invalid email or password' });
        }
    } catch (error) {
        return res.status(500).json({ msg: "Server Error. try again later" });
    }
});

app.post('/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: true,
        sameSite: 'none'
    });
    res.status(200).send('Logged out successfully');
});

app.delete('/account', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send('No token');

    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;

        const { emailDel, textDel } = req.body;
        if (typeof emailDel !== 'string' || !emailDel.includes('@')) {
            return res.status(400).send('Invalid email');
        }
        if (!textDel) {
            return res.status(400).send('bad request: provide necessary text');
        }
        if (textDel !== 'DELETE') {
            return res.status(400).send("input must be <span style='font-weight: bold; font-family: Poppins, calibri;'>'DELETE'</span>");
        }
        const confirmID = await User.findOne({ _id: userId });
        if (emailDel !== confirmID.email) {
            return res.status(400).send('Invalid email (provide the email tied to this account)');
        }

        // const deletedUser = await User.findByIdAndDelete(userId);
        const deletedUser = await User.findByIdAndDelete(userId);
        if (!deletedUser) return res.status(404).send('User not found');
        await QRCode.deleteMany({ createdBy: userId });

        res.clearCookie('token', {
            httpOnly: true,
            secure: true,
            sameSite: 'none'
        });
        res.status(200).send('Account deleted successfully');
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).send('Token is invalid. Log in and try again');
        }
        return res.status(500).send('Server error. Please try again');
    }
});

app.post('/api/genqrcode', async (req, res) => {
    if (!req.body) {
        return res.status(400).json({ msg: 'No data provided' });
    }
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        const { url, title } = req.body;
        if (!isValidUrl(url)) {
            return res.status(400).json({ msg: 'Invalid URL format' });
        }
        const newQR = new QRCode({ createdBy: userId, url: url, title: title });
        await newQR.save();
        const dynamicUrl = `${BASE_URL}/redirect/${newQR._id}`;
        try {
            const qrDataUrl = await QRcode.toDataURL(dynamicUrl);
            return res.status(201).json({ qrImageUrl: qrDataUrl, msg: 'QR code generated successfully' });
        } catch (error) {
            await QRCode.findByIdAndDelete(newQR._id);
            return res.status(500).json({ msg: 'Error generating QR code' });
        }
    } catch (error) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
});

app.get('/redirect/:id', async (req, res) => {
    const qrId = req.params.id;

    const ip =
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress;

    const userAgent = req.headers['user-agent'];

    try {
        const qrCode = await QRCode.findById(qrId);
        if (!qrCode) {
            return res.status(404).send('QR code not found');
        }

        // Prevent duplicate scans within last 5 seconds
        const recentScan = await ScanLog.findOne({
            qrId: qrCode._id,
            ip,
            createdAt: { $gt: new Date(Date.now() - 5000) }
        });

        if (!recentScan) {
            await ScanLog.create({
                qrId: qrCode._id,
                userId: qrCode.createdBy,
                ip,
                userAgent
            });

            qrCode.clicks++;
            await qrCode.save();
        }

        return res.redirect(qrCode.url);

    } catch (err) {
        console.error(err);
        return res.status(500).send('Server error');
    }
});

app.get('/api/qrcode', async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        const qrCodes = await QRCode.find({ createdBy: userId });
        if (!qrCodes || qrCodes.length === 0) {
            return res.status(404).json({ msg: 'No QR codes found' });
        }
        const qrCodesWithImage = await Promise.all(
            qrCodes.map(async (doc) => {
                const qrDataUrl = await QRcode.toDataURL(`http://localhost:3000/redirect/${doc._id}`);
                return {
                    ...doc.toObject(),
                    qrDataUrl
                };
            })
        );

        return res.status(200).json({ qrCodes: qrCodesWithImage });
    } catch (error) {
        return res.status(401).json({ msg: error.message });
    }
});

app.delete('/api/qrcode/:id', async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        const qrId = req.params.id;
        const qrCode = await QRCode.findById(qrId);
        if (!qrCode) {
            return res.status(404).json({ msg: 'QR code not found' });
        }
        if (qrCode.createdBy.toString() !== userId) {
            return res.status(403).json({ msg: 'Forbidden' });
        }
        await QRCode.findByIdAndDelete(qrId);
        return res.status(200).json({ msg: 'QR code deleted successfully' });
    } catch (error) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
});

app.patch('/api/qrcode/:id', async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        const qrId = req.params.id;
        const { title, url } = req.body;
        const qrCode = await QRCode.findById(qrId);
        if (!qrCode) {
            return res.status(404).json({ msg: 'QR code not found' });
        }
        if (qrCode.createdBy.toString() !== userId) {
            return res.status(403).json({ msg: 'Forbidden' });
        }
        if (title) qrCode.title = title;
        if (url) {
            if (!isValidUrl(url)) {
                return res.status(400).json({ msg: 'Invalid URL format' });
            }
            qrCode.url = url;
        }
        qrCode.dateModified = Date.now();
        await qrCode.save();
        return res.status(200).json({ msg: 'QR code updated successfully' });
    } catch (error) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
});

app.get('/api/overview', async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        const qrCodes = await QRCode.find({ createdBy: userId }).sort({ dateModified: -1, dateCreated: -1 }).limit(6);
        if (!qrCodes || qrCodes.length === 0) {
            return res.status(404).json({ msg: 'No QR codes found' });
        }
        const qrCodesWithImage = await Promise.all(
            qrCodes.map(async (doc) => {
                const qrDataUrl = await QRcode.toDataURL(`${BASE_URL}/redirect/${doc._id}`);
                return {
                    ...doc.toObject(),
                    qrDataUrl
                };
            })
        );



        const totalQRCodes = await QRCode.countDocuments({ createdBy: userId });
        const totalScansAgg = await QRCode.aggregate([
            { $match: { createdBy: new mongoose.Types.ObjectId(userId) } },
            { $group: { _id: null, totalClicks: { $sum: "$clicks" } } }
        ]);
        const totalScans = totalScansAgg[0] ? totalScansAgg[0].totalClicks : 0;
        const last7Days = new Date();
        last7Days.setDate(last7Days.getDate() - 7);

        let scans = [];
        try {
            scans = await ScanLog.aggregate([
                { $match: { userId: new mongoose.Types.ObjectId(userId), timestamp: { $gte: last7Days } } },
                {
                    $group: {
                        _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
                        count: { $sum: 1 },
                    },
                },
                { $sort: { _id: 1 } }, // oldest to newest
            ]);
        } catch (error) {
            console.error("Scan log error:", error);
            scans = [];
            return res.status(500).json({ msg: "Error retrieving scan log" });
        }
        return res.status(200).json({ scans, recentQrCodes: qrCodesWithImage, totalQRCodes, totalScans });
    } catch (error) {
        return res.status(401).json({ msg: error.message });
    }
});


const start = async () => {
    try {
        await connectDB(process.env.MONGO_URI);
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`server is listening on port ${PORT}...`);
        });
    } catch (error) {
        console.log(error);
    }
}

start();
