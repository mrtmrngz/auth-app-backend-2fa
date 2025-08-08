import CustomError from "../helpers/customError.js";
import generateOTP from "../helpers/generateOTP.js";
import {sendMail} from "../libs/sendMail.js";

export const register_controller = async (req, res, next) => {

    const {username, email, password} = req.body

    if (!username) {
        return next(new CustomError("Username cannot be empty", 400))
    }

    if (!email) {
        return next(new CustomError("Email cannot be empty", 400))
    }

    if (!password) {
        return next(new CustomError("Password cannot be empty", 400))
    }

    const verifyAccountToken = generateOTP()

    await sendMail({
        from: {
            name: "Nodejs Auth App",
            address: process.env.APP_MAIL,
        },
        to: email,
        subject: "Verify Account",
        html: "geminiye yazdır  sendmail adında yerden gönder maili"
    })

    res.status(200).json({ success: true, message: "Kayıt başarılı."});
}