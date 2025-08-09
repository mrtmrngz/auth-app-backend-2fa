import CustomError from "../helpers/customError.js";
import generateOTP from "../helpers/generateOTP.js";
import {sendOTPMAIL} from "../libs/sendMail.js";
import User from "../models/User.model.js";
import bcrypt from 'bcrypt'
import {generateAccessToken, generateMailToken} from "../libs/generateTokens.js";
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

export const verify_otp = async (req, res, next) => {
    const { token, otp, otpType: bodyOtpType } = req.body;

    if (!token || !otp) {
        return next(new CustomError("OTP and Token are required", 400));
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_MAIL_SECRET);

        const user = await User.findById(payload.id);

        if (!user) return next(new CustomError("Invalid OTP or user not found", 404));

        if(bodyOtpType === "VERIFY_ACCOUNT" && user.isVerified) return res.status(200).json({message: "User already verified"})

        if (user.otpType !== bodyOtpType) return next(new CustomError("Unauthorized OTP type", 403));

        if (user.otpExpire < new Date()) return next(new CustomError("OTP expired. Please resend code again.", 400));

        if(otp.trim() === user.otp) {

            if(bodyOtpType === "VERIFY_ACCOUNT") {
                user.isVerified = true;
            }
            user.otp = undefined;
            user.otpType = undefined;
            user.otpExpire = undefined;
            user.otpAttemps = undefined
            await user.save();

            if(bodyOtpType === "VERIFY_ACCOUNT") {
                return  res.status(200).json({ success: true, message: "Email verified, please login!" });
            }else if(bodyOtpType === "TWO_FACTOR") {
                // const accessToken = generateAccessToken(user._id, user.role)
                const accessToken = "token"   //generate access and refresh token  (save refresh token http only cookie!)
                return  res.status(200).json({ success: true, message: "Login Successfull", accessToken });
            }

        }else {

            const userOtpAttemps = user.otpAttemps || 0

            if(userOtpAttemps >= 4) {
                if(bodyOtpType === "VERIFY_ACCOUNT") {
                    await user.deleteOne()
                    return next(new CustomError("Too many failed attempts. Your account has been deleted. Please register again.", 403));
                }else if(bodyOtpType === "TWO_FACTOR") {
                    user.isUserLocked = true
                    user.userLockExpire = new Date(Date.now() + (1000 * 60 * 10))
                    await user.save()
                    return next(new CustomError("Too many failed attempts. Your account has been locked. Please register again.", 429));
                }
            }else {
                user.otpAttemps = (userOtpAttemps || 0) + 1
                await user.save()
                return next(new CustomError("Invalid Code", 400))
            }
        }

    } catch (err) {
        if (err.name === "TokenExpiredError") {
            return next(new CustomError("OTP expired. Please register again.", 401));
        }

        console.error("Verify OTP Error:", err);
        return next(new CustomError("An error occurred during OTP verification.", 500));
    }
};

export const resend_otp = async (req, res, next) => {
    const { token, otpType } = req.body;

    if (!token) {
        return next(new CustomError("OTP and Token are required", 400));
    }

    if(!otpType)  return next(new CustomError("OTP type is required", 400));

    try {

        const decodedToken = jwt.verify(token, process.env.JWT_MAIL_SECRET, { ignoreExpiration: true })

        if (!decodedToken || !decodedToken.id) {
            return next(new CustomError("Invalid or corrupted token.", 401));
        }

        if(decodedToken.otpType !== otpType) return next(new CustomError("Invalid OTP type", 403))

        const user = await User.findById(decodedToken.id)

        if(!user) return next(new CustomError("User not found", 404))

        if(decodedToken.otpType === "TWO_FACTOR" && user.isUserLocked) {
            if(new Date() > user.userLockExpire){
                user.isUserLocked = undefined
                user.userLockExpire = undefined
                user.otpAttemps = undefined
                await user.save()
            }else {
                const unlockDate = user.userLockExpire;
                const unlockTime = unlockDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                return next(new CustomError(
                    `Your account is locked please try ${unlockTime}`,
                    403
                ))
            }
        }

        const newOtp = generateOTP()
        const newToken = generateMailToken(otpType ,user._id)

        user.otp = newOtp
        user.otpExpire = new Date(Date.now() + (1000 * 60 * 5))

        await Promise.all([
            user.save(),
            sendOTPMAIL({otp: newOtp, email:user.email})
        ])

        return res.status(200).json({success: true, message: "The code has been sent to your email address", token: newToken})

    } catch (err) {
        console.error("Verify OTP Error:", err);
        return next(new CustomError("An error occurred during OTP verification.", 500));
    }
};

export const login = async (req, res, next) => {

    const { email, password } = req.body

    try {
        //codes
    } catch (err) {
        return next(new CustomError("An error occurred during login.", 500));
    }
};

export const get_token = async (req, res, next) => {

    try {
        //codes
    } catch (err) {
        return next(new CustomError("An error occurred during login.", 500));
    }
};

export const logout = async (req, res, next) => {

    try {
        //codes
    } catch (err) {
        return next(new CustomError("An error occurred during login.", 500));
    }
};