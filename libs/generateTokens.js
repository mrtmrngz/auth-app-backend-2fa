import jwt from 'jsonwebtoken'

export const generateMailToken = (otpType, userId) => {
    return jwt.sign({id: userId, otpType: otpType}, process.env.JWT_MAIL_SECRET, { expiresIn: "5m" })
}