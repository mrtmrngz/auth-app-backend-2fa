import CustomError from "../helpers/customError.js";
import User from "../models/User.model.js";
import {send_two_factor_mail} from "../helpers/two-factor-mail.js";


export const user_info = async (req, res, next) => {

    try {
        const user = await User.findById(req.user.id).select("user email avatar role isVerified")

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