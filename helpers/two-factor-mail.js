import CustomError from "./customError.js";
import {generateMailToken} from "../libs/generateTokens.js";
import {sendOTPMAIL} from "../libs/sendMail.js";
import generateOTP from "./generateOTP.js";


export async function send_two_factor_mail(user, changeType="TWO_FACTOR", otp=undefined){
    if(!user) {
        throw new CustomError("User required", 400)
    }

    const allowedTypes = ["TWO_FACTOR", "EMAIL_CHANGE", "USERNAME_CHANGE"]

    if(!allowedTypes.includes(changeType)) throw new CustomError("Invalid Change Type!", 403)


    let currentOtp;

    if(otp) {
        currentOtp = otp
    }

    try {

        if(changeType === "TWO_FACTOR") {
            const two_factor_otp = generateOTP()
            user.otp = two_factor_otp
            user.otpType = changeType
            user.otpExpire = new Date(Date.now() + (1000 * 60 * 5))
            await user.save()
            currentOtp = two_factor_otp
        }

        const two_factor_token = generateMailToken(changeType, user._id)

        const mailType = changeType === "TWO_FACTOR" ? "Two Factor Authentication Code" : changeType === "EMAIL_CHANGE" ? "Email Change OTP Code" : "Username Change OTP Code"

        let returnMessage;

        if(changeType === "TWO_FACTOR" || changeType === "USERNAME_CHANGE") {
            await sendOTPMAIL({otp:currentOtp, email:user.email, type: mailType})
            returnMessage = "The 6-digit code has been sent to your email address."
        }else if (changeType === "EMAIL_CHANGE") {
            await sendOTPMAIL({otp:currentOtp, email:user.newEmail, type: mailType})
            returnMessage = "The 6-digit code has been sent to your new email address."
        }


        return { token: two_factor_token, message: returnMessage }

    }catch (err) {
        console.log(err);
        throw new CustomError("Somethings goes wrong during sending otp!", 500)
    }
}