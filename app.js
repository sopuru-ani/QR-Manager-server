import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import QRcode from 'qrcode';
import mongoose from 'mongoose';
import { Resend } from 'resend';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';

import connectDB from './db/connect.js';
import User from './model/User.js';
import QRCode from './model/QRcodes.js';
import ScanLog from './model/ScanLogs.js';
import Verifies from './model/Verify.js';


dotenv.config();

//import { transporter } from './email.js';
const app = express();
const PORT = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET;
const exp = process.env.JWT_LIMIT;
const resend = new Resend(process.env.RESEND_API_KEY);
// const BASE_URL = "https://qr-manager-server-gec1.onrender.com";
const BASE_URL = "https://server.qr-manager.net";



// Middleware
app.set("trust proxy", 1);
const corsOptions = {
  origin: ["https://qr-manager-beige.vercel.app", "https://www.qr-manager.net"],
  // origin: "https://qr-manager-beige.vercel.app",
  credentials: true,  // important for cookies
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
// app.use(cors({
//   origin: "https://qr-manager.net",
//     credentials: true,
//     methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
//     allowedHeaders: ["Content-Type", "Authorization"],
// }));
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
        const profile = await User.find({ _id: userId }).select('firstName lastName email avatar googleAuth hashedPassword');
        console.log(profile);
        return res.status(200).json(profile);
    } catch (error) {
        return res.status(500).json({ msg: 'Unauthorized' })
    }
});
//Login and signup routes would go here
app.post('/auth/send-code', async (req, res) => {
    try {
        if (!req.body) {
            return res.status(400).json({ msg: 'No email provided' });
        }
        const { email } = req.body;
        const dontsignup = await User.findOne({ email: email });
        if (dontsignup) {
            return res.status(400).json({ msg: 'Email already in use' });
        }
        const code = Math.floor(100000 + Math.random() * 900000);
        await Verifies.findOneAndUpdate(
            { email },
            {
                code,
                createdAt: new Date() // reset timer
            },
            { upsert: true, new: true }
        );
        await resend.emails.send({
            from: "QR Manager <no-reply@qr-manager.net>",
            to: email,
            subject: "Your QR-Manager Verification Code",
            html: `
  <div style="font-family:Arial, Helvetica, sans-serif; padding:20px; background:#f7f8fa;">
      
      <div style="max-width:520px; margin:auto; background:white; padding:30px; border-radius:10px; 
                  border:1px solid #e5e7eb; box-shadow:0 4px 18px rgba(0,0,0,0.04);">

          <div style="text-align:center;">
              <h1 style="margin:0; font-size:24px; color:#1e293b; font-weight:700;">
                  Email Verification
              </h1>
              <p style="color:#475569; font-size:14px; margin-top:8px; line-height:1.5;">
                  Use the code below to verify your email.<br/>
                  This code expires in <strong>10 minutes</strong>.
              </p>
          </div>

          <div style="margin:26px 0; text-align:center;">
              <div style="background:#4caf50; color:white; padding:14px 32px; 
                          font-size:22px; font-weight:700; letter-spacing:2px; 
                          border-radius:8px; display:inline-block;">
                  ${code}
              </div>
          </div>

          <hr style="margin:30px 0; border:none; border-top:1px solid #e2e8f0" />

          <p style="font-size:12px; color:#94a3b8; text-align:center;">
              If you didn’t request this, you can safely ignore this email.
          </p>
      </div>

      <p style="text-align:center; margin-top:14px; font-size:12px; color:#4caf50;">
          © 2025 QR-Manager. All rights reserved.
      </p>

  </div>
  `
        });
        res.status(200).json({ msg: true });
    } catch (error) {
        console.log(error);
        res.status(400).json({msg: error});
    }


});

app.post('/auth/verify-code', async (req, res) => {
    if (!req.body) {
        return res.status(400).json({ msg: 'No data provided(i need the email and code now...)' });
    }
    if (!req.body.code) {
        return res.status(400).json({ msg: 'No code provided' });
    }
    const { email, code } = req.body;
    const match = await Verifies.findOne({ email, code });
    if (!match) {
        return res.status(404).json({ msg: false });
    }
    res.status(200).json({ msg: true });
});

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
            httpOnly: true,    // Prevent frontend JS from reading it
            secure: true,     // Set to true in production (HTTPS)
            sameSite: 'None',
            domain: '.qr-manager.net'
        });
        return res.status(201).json({ msg: 'Account created successfully. redirecting...' });
    } catch (error) {
        return res.status(500).json({ msg: "Server Error. try again later" });
    }
});

const loginUser = (user, res) => {
    const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: exp });

    res.cookie('token', token, {
          httpOnly: true,    // Prevent frontend JS from reading it
          secure: true,     // Set to true in production (HTTPS)
          sameSite: 'None',
          domain: '.qr-manager.net'
    });

    res.status(200).json({ msg: "Login Successful! Redirecting to dashboard now..." });
}
app.post('/googlesignup', async (req, res) => {
    try {
        const { googleId, name, email, picture } = req.body;
        console.log(req.body);
        // console.log(email);

        const user = await User.findOne({ email: email });
        console.log(user);

        if (user && user.googleAuth) {
            return loginUser(user, res);
        }

        if (user && !user.googleAuth) {
            user.googleAuth = true;
            user.googleId = googleId;
            user.avatar = picture;
            await user.save();
            return loginUser(user, res);
        }
        // const [firstName, ...rest] = name.split(" ");
        // const lastName = rest.join(" ");
        console.log("last step");
        const newUser = new User({
            firstName: name.split(" ")[0] || " ",
            lastName: name.split(" ")[1] || " ",
            email: email,
            googleAuth: true,
            googleId: googleId,
            avatar: picture,
        });
        console.log(newUser);

        await newUser.save();
        return loginUser(newUser, res);

    } catch (error) {
        return res.status(401).json({ msg: 'Unauthorized' });
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
    if (user.googleAuth === true && !user.hashedPassword) {
        return res.status(400).json({ msg: "This email is registered with Google. Sign in using Google instead." });
    }
    try {
        if (await bcrypt.compare(password, user.hashedPassword)) {
            const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: exp });
            res.cookie('token', token, {
              httpOnly: true,    // Prevent frontend JS from reading it
              secure: true,     // Set to true in production (HTTPS)
              sameSite: 'None',
              domain: '.qr-manager.net'
            });
            return res.status(200).json({ msg: 'Login successful. redirecting...' });
        } else {
            return res.status(400).json({ msg: 'Invalid email or password' });
        }
    } catch (error) {
        return res.status(500).json({ msg: "Server Error. try again later" });
    }
});

app.patch('/addpassword', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ msg: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        if (!req.body) {
            return res.status(400).json({ msg: 'Both fields are required' });
        }
        const { password, confirmPassword } = req.body;
        if (!password || !confirmPassword) {
            return res.status(400).json({ msg: 'Both fields are required' });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ msg: 'Both passwords must match' });
        }
        const user = await User.findOne({ _id: userId });
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);
        user.hashedPassword = hashedPassword;
        await user.save();
        return res.status(200).json({ msg: 'Password added successfully!' });
    } catch (error) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }
});

app.patch('/changepassword', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ msg: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;
        if (!req.body) {
            return res.status(400).json({ msg: 'Both fields are required' });
        }
        const { currentPassword, newPassword, confirmPassword } = req.body;
        if (!newPassword || !confirmPassword || !currentPassword) {
            return res.status(400).json({ msg: 'All fields are required' });
        }
        const user = await User.findOne({ _id: userId });
        const passwordMatch = await bcrypt.compare(currentPassword, user.hashedPassword);
        if (!passwordMatch) {
            return res.status(400).json({ msg: 'Current password is invalid' });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ msg: 'Both passwords must match' });
        }
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        user.hashedPassword = hashedPassword;
        await user.save();
        return res.status(200).json({ msg: 'Password changed successfully!' });
    } catch (error) {
        return res.status(401).json({ msg: 'Unauthorized' });
    }

});

app.post('/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        domain: '.qr-manager.net'
    });
    res.status(200).send('Logged out successfully');
});

app.delete('/account', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ msg: 'No token' });

    try {
        const decoded = jwt.verify(token, secretKey);
        const userId = decoded.userId;

        const { emailDel, textDel } = req.body;
        if (typeof emailDel !== 'string' || !emailDel.includes('@')) {
            return res.status(400).json({ msg: 'Invalid email' });
        }
        if (!textDel) {
            return res.status(400).json({ msg: 'bad request: provide necessary text' });
        }
        if (textDel !== 'DELETE') {
            // return res.status(400).json({ msg: "input must be <span style='font-weight: bold; font-family: Poppins, calibri;'>'DELETE'</span>" });
            return res.status(400).json({ msg: "Input must be 'DELETE'" });
        }
        const confirmID = await User.findOne({ _id: userId });
        if (emailDel !== confirmID.email) {
            return res.status(400).json({ msg: 'Invalid email (provide the email tied to this account)' });
        }

        // const deletedUser = await User.findByIdAndDelete(userId);
        const deletedUser = await User.findByIdAndDelete(userId);
        if (!deletedUser) return res.status(404).json({ msg: 'User not found' });
        await QRCode.deleteMany({ createdBy: userId });

        res.clearCookie('token', {
          httpOnly: true,
          secure: true,
          sameSite: 'None',
          domain: '.qr-manager.net'
        });
        res.status(200).json({ msg: 'Account deleted successfully' });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ msg: 'Token is invalid. Log in and try again' });
        }
        return res.status(500).json({ msg: 'Server error. Please try again' });
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
                const qrDataUrl = await QRcode.toDataURL(`${BASE_URL}/redirect/${doc._id}`);
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

app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ msg: "Email is required." });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "No account with this email exists." });

    // Generate token
    const token = crypto.randomBytes(32).toString("hex");

    // Save hashed version (safer)
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    user.resetToken = hashedToken;
    user.resetTokenExpires = Date.now() + (1000 * 60 * 10); // 15 mins expiration
    await user.save();

    const resetURL = `https://qr-manager.net/reset-password?token=${token}`;

    // Send email via Resend
    await resend.emails.send({
        from: "QR Manager <no-reply@qr-manager.net>",
        to: user.email,
        subject: "Reset Your QR-Manager Password",
        html: `
  <div style="font-family:Arial, Helvetica, sans-serif; padding:20px; background:#f7f8fa;">
      
      <div style="max-width:520px; margin:auto; background:white; padding:30px; border-radius:10px; 
                  border:1px solid #e5e7eb; box-shadow:0 4px 18px rgba(0,0,0,0.04);">

          <div style="text-align:center;">
              <h1 style="margin:0; font-size:24px; color:#1e293b; font-weight:700;">
                QR-Manager Password Reset
              </h1>
              <p style="color:#475569; font-size:14px; margin-top:8px;">
                  You requested to reset your password.<br/>
                  This link expires in <strong>15 minutes</strong>.
              </p>
          </div>

          <div style="margin:26px 0; text-align:center;">
              <a href="${resetURL}" 
                 style="background:#2563eb; color:white; padding:12px 22px; font-size:15px; 
                        font-weight:600; border-radius:8px; text-decoration:none; display:inline-block;">
                 Reset Password
              </a>
          </div>

          <p style="color:#475569; font-size:14px; line-height:1.6;">
              If the button doesn’t work, paste this link in your browser:
              <br><br>
              <span style="display:block; word-break:break-all; color:#1d4ed8; font-size:13px;">
                  ${resetURL}
              </span>
          </p>

          <hr style="margin:30px 0; border:none; border-top:1px solid #e2e8f0" />

          <p style="font-size:12px; color:#94a3b8; text-align:center;">
              If you didn’t request this, you can safely ignore this email.
          </p>
      </div>

      <p style="text-align:center; margin-top:14px; font-size:12px; color:#a1a1aa;">
          © 2025 QR-Manager. All rights reserved.
      </p>

  </div>
  `
    });

    return res.status(200).json({ msg: "Password reset email sent." });
});

app.post("/verify-token", async (req, res) => {
    const { token } = req.body;

    if (!token) return res.status(400).json({ msg: "Data missing." });

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
        resetToken: hashedToken,
        resetTokenExpires: { $gt: Date.now() } // not expired
    });

    if (!user) return res.status(401).json({ msg: "Invalid or expired reset token." });
    return res.status(200).json({ msg: "Valid token" });

});

app.post("/reset-password", async (req, res) => {
    const { token, password, confirmPassword } = req.body;

    if (!token || !password || !confirmPassword) return res.status(400).json({ msg: "Data missing." });
    if (password !== confirmPassword) return res.status(400).json({ msg: "Passwords must match" });

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
        resetToken: hashedToken,
        resetTokenExpires: { $gt: Date.now() } // not expired
    });

    if (!user) return res.status(401).json({ msg: "Invalid or expired reset token." });

    // hash new password
    const salt = await bcrypt.genSalt();
    user.hashedPassword = await bcrypt.hash(password, salt);

    // clear token so link can't be reused
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;

    await user.save();

    return res.json({ msg: "Password reset successful. redirecting to signup..." });
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
