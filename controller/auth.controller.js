import CustomError from "../helpers/customError.js";
import generateOTP from "../helpers/generateOTP.js";
import {sendOTPMAIL} from "../libs/sendMail.js";
import User from "../models/User.model.js";
import bcrypt from 'bcrypt'
import {generateMailToken} from "../libs/generateTokens.js";
import jwt from "jsonwebtoken";

export const register_controller = async (req, res, next) => {

    const {username, email, password} = req.body

    try {

        if (!username) {
            return next(new CustomError("Username cannot be empty", 400))
        }

        if (!email) {
            return next(new CustomError("Email cannot be empty", 400))
        }

        if (!password) {
            return next(new CustomError("Password cannot be empty", 400))
        }

        const [existingUserByEmail, existingUserByUsername] = await Promise.all([
            User.findOne({email}),
            User.findOne({username})
        ])

        if (existingUserByEmail || existingUserByUsername) return next(new CustomError("User already exist!", 400))

        const hashedPassword = await bcrypt.hash(password, 10)

        const verifyAccountOTP = generateOTP()

        const newUser = await new User({
            email,
            username,
            password: hashedPassword,
            otp: verifyAccountOTP,
            otpExpire: new Date(Date.now() + (1000 * 60 * 5))
        })

        await newUser.save()

        const otpToken = generateMailToken("VERIFY_ACCOUNT", newUser._id)

        await sendOTPMAIL({otp: verifyAccountOTP, email})

        res.status(200).json({success: true, message: "Register successful please check your email!", token: otpToken});
    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during registration.", 500));
    }
}

export const verify_account = async (req, res, next) => {
    const { token, otp } = req.body;

    if (!token || !otp) {
        return next(new CustomError("OTP and Token are required", 400));
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_MAIL_SECRET);

        const user = await User.findOne({ _id: payload.id, otp });

        if (!user) return next(new CustomError("Invalid OTP or user not found", 404));

        if (user.otpType !== "VERIFY_ACCOUNT") return next(new CustomError("Unauthorized OTP type", 403));

        if (user.otpExpire < Date.now()) return next(new CustomError("OTP expired. Please register again.", 400));

        user.isVerified = true;
        user.otp = undefined;
        user.otpType = undefined;
        user.otpExpire = undefined;
        await user.save();

        res.status(200).json({ success: true, message: "Email verified, please login!" });

    } catch (err) {
        if (err.name === "TokenExpiredError") {
            return next(new CustomError("OTP expired. Please register again.", 401));
        }

        console.error("Verify OTP Error:", err);
        return next(new CustomError("An error occurred during OTP verification.", 500));
    }
};

export const resend_otp = async (req, res, next) => {
    const { token } = req.body;

    if (!token) {
        return next(new CustomError("OTP and Token are required", 400));
    }

    try {

        const decodedToken = jwt.decode(token, process.env.JWT_MAIL_SECRET)

        if (!decodedToken || !decodedToken.id) {
            return next(new CustomError("Invalid or corrupted token.", 401));
        }

        const user = await User.findById(decodedToken.id)

        if(!user) return next(new CustomError("User not found", 404))

        const newOtp = generateOTP()
        const newToken = generateMailToken("VERIFY_ACCOUNT",user._id)

        user.otp = newOtp
        user.otpExpire = new Date(Date.now() + (1000 * 60 * 5))
        await user.save()

        await sendOTPMAIL({otp: newOtp, email:user.email})

        return res.status(200).json({success: true, message: "The code has been sent to your email address", token: newToken})

    } catch (err) {
        console.error("Verify OTP Error:", err);
        return next(new CustomError("An error occurred during OTP verification.", 500));
    }
};