import mongoose from "mongoose";

const UserSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        select: false
    },
    avatar: {
        type: String,
        default: "https://res.cloudinary.com/mertmarangoz/image/upload/v1754666049/d8b5d0a738295345ebd8934b859fa1fca1c8c6ad_qtxbzf.jpg"
    },
    role: {
        type: String,
        enum: ["USER", "ADMIN"],
        default: "USER"
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    isTwoFactorEnabled: { type: Boolean, default: false },
    resetPasswordToken: { type: String },
    resetPasswordTokenExpire: { type: Date },
    otpType: {
        type:String,
        enum: ["VERIFY_ACCOUNT", "TWO_FACTOR"]
    },
    otp: {
        type: String,
    },
    otpExpire: {type: Date},
    otpAttemps: { type: Number },
    isUserLocked: { type: Boolean },
    userLockExpire: { type: Date }
}, { timestamps: true })

const User = mongoose.model('User', UserSchema)

export default User