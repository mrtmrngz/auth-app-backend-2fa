import nodemailer from 'nodemailer'
import {OTP_TEMPLATE} from "../helpers/htmlTemplates.js";

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.APP_MAIL,
        pass: process.env.APP_PASSWORD
    }
})

export const sendMail = async (mailOptions) => {
    try {
        await transporter.sendMail(mailOptions)
    }catch (err) {
        console.log(`Email error ${err}`)
        throw err
    }
}

export const sendOTPMAIL = async ({ otp, email, type = "Email Verification" }) => {
    await sendMail({
        from: {
            name: "Nodejs Auth App",
            address: process.env.APP_MAIL,
        },
        to: email,
        subject: type,
        html: OTP_TEMPLATE.replace("{{email content}}", type).replace("{{ otp_code }}", otp)
    })
}