import CustomError from "../helpers/customError.js";
import User from "../models/User.model.js";
import {send_two_factor_mail} from "../helpers/two-factor-mail.js";
import generateOTP from "../helpers/generateOTP.js";
import {cloudinary} from "../libs/cloudinary.js";


export const user_info = async (req, res, next) => {

    try {
        const user = await User.findById(req.user.id).select("username email avatar role isVerified")

        if(!user) return next(new CustomError("User not found", 404))

        if(!user.isVerified) {
            return next(new CustomError("Email not verified. Please verified your email first", 409))
        }

        res.status(200).json(user)
    }catch (err) {
        return next(new CustomError("An error occurred during fetching user info.", 500));
    }
}

export const enable_two_factor = async (req, res, next) => {
    try {

        const user = await User.findById(req.user.id).select("email isTwoFactorEnabled")

        if(!user) return next(new CustomError("User not found", 404))

        if(user.isTwoFactorEnabled) {
            return next(new CustomError("2FA already active", 409))
        }

        const { token, message } = await send_two_factor_mail(user)

        return res.status(200).json({success: true, message, token})


    }catch (err) {
        return next(new CustomError("An error occurred during enabled 2FA.", 500));
    }
}

export const change_mail_or_username = async (req, res, next) => {

    const {username, email, changeType} = req.body
    const tokenUserId = req.user.id

    if(!changeType) {
        return next(new CustomError("Change type is required", 400))
    }

    if(changeType !== "EMAIL_CHANGE" && changeType !== "USERNAME_CHANGE") return next(new CustomError("Invalid Change Type", 400))
    if(changeType === "EMAIL_CHANGE" && (!email || email.trim() === "")) return next(new CustomError("Email Required", 400))
    if(changeType === "USERNAME_CHANGE" && (!username || username.trim() === "")) return next(new CustomError("Username Required", 400))

    try {

        const user = await User.findById(tokenUserId)

        if(!user) return next(new CustomError("User not found", 404))

        if(changeType === "EMAIL_CHANGE") {
            const existingUserEmail = await User.findOne({email: email})

            if(existingUserEmail) return next(new CustomError("Existing user!", 400))

            user.newEmail = email

        }else if (changeType === "USERNAME_CHANGE") {
            const existingUserUsername = await User.findOne({username: username})

            if(existingUserUsername) return next(new CustomError("Existing user!", 400))

            user.newUsername = username
        }

        const otp = generateOTP()
        user.otp = otp
        user.otpType = changeType
        user.otpExpire = new Date(Date.now() + (1000 * 60 * 5))
        await user.save()

        const {token, message} = await send_two_factor_mail(user)

        return res.status(200).json({success: true, message: message, token})


    }catch (err) {
        return next(new CustomError("An error occurred during profile info change.", 500));
    }
}

export const change_other_infos = async (req, res, next) => {


    const tokenUserId = req.user.id
    const uploadedFile = req.file

    try {

        const user = await User.findById(tokenUserId)

        if(!user) return next(new CustomError("User not found", 404))

        if(uploadedFile) {

            if(user.avatar && user.avatar.public_id) {
                await cloudinary.uploader.destroy(user.avatar.public_id)
            }

            const result = await cloudinary.uploader.upload(`data:${uploadedFile.mimetype};base64,${uploadedFile.buffer.toString('base64')}`, {
                folder: "auth-app"
            })

            user.avatar.url = result.url
            user.avatar.public_id = result.public_id
        }

        await user.save()

        res.status(200).json({message: "User updated successfully!", success: true})


    }catch (err) {
        console.log(err)
        return next(new CustomError("An error occurred during profile info change.", 500));
    }
}
