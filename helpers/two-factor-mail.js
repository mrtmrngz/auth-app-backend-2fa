import CustomError from "./customError.js";
import {generateMailToken} from "../libs/generateTokens.js";
import {sendOTPMAIL} from "../libs/sendMail.js";
import generateOTP from "./generateOTP.js";


export async function send_two_factor_mail(user){
    if(!user) {
        throw new CustomError("User required", 400)
    }
    try {
        const two_factor_otp = generateOTP()

        user.otp = two_factor_otp
        user.otpType = "TWO_FACTOR"
        user.otpExpire = new Date(Date.now() + (1000 * 60 * 5))
        await user.save()

        const two_factor_token = generateMailToken("TWO_FACTOR", user._id)

        await sendOTPMAIL({otp:two_factor_otp, email:user.email, type: "Two Factor Authentication Code"})

        return { token: two_factor_token, message: "The 6-digit code has been sent to your email address." }

    }catch (err) {
        throw new CustomError("Somethings goes wrong during sending otp!", 500)
    }
}