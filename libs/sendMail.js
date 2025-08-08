import nodemailer from 'nodemailer'

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