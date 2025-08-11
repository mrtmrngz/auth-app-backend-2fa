import mongoose from "mongoose";

const UserSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    newUsername: {
        type: String,
        unique: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    newEmail: {
        type: String,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        select: false
    },
    avatar: {
        url: {
            type: String,
        },
        public_id: {
            type: String,
        }
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
        enum: ["VERIFY_ACCOUNT", "TWO_FACTOR", "USERNAME_CHANGE", "EMAIL_CHANGE"]
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