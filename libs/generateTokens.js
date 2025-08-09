import jwt from 'jsonwebtoken'

export const generateMailToken = (otpType, userId) => {
    return jwt.sign({id: userId, otpType: otpType}, process.env.JWT_MAIL_SECRET, { expiresIn: "5m" })
}

export const generateAccessToken = (userId, role) => {
    return jwt.sign({id: userId, role: role}, process.env.JWT_ACCESS_SECRET, {expiresIn: "15m"})
}

export const generateRefreshToken = (userId, role) => {
    return jwt.sign({id: userId, role: role}, process.env.JWT_REFRESH_SECRET, {expiresIn: "7d"})
}