import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import helmet from "helmet";
import morgan from 'morgan'
import mainRoutes from './routes/index.js'
import errorMiddleware from "./middlewares/errorMiddleware.js";
import connectDB from "./libs/connectDb.js";
import {verify_token} from "./middlewares/verify-token.js";
import {safe_unban_user} from "./libs/schedule.js";

if (process.env.NODE_ENV !== "test") {
    connectDB()
}

const app = express()

app.use(express.json())
app.use(express.urlencoded({extended: true}))
app.use(cookieParser())
app.use(helmet())
app.use(helmet.crossOriginResourcePolicy({policy: 'cross-origin'}))
app.use(morgan('common'))
app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true
}))

const tokenLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: process.env.NODE_ENV === "test" ? Infinity : 100,
    message: {
        status: 429,
        message: "You have sent too many requests, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
})

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        status: 429,
        message: "You have sent too many requests, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
})

const other_auth_limits = rateLimit({
    windowMs: 60 * 1000,
    max: process.env.NODE_ENV === "test" ? Infinity : 35,
    message: {
        status: 429,
        message: "You have sent too many requests, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
})

const register_login_limit = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: process.env.NODE_ENV === "test" ? Infinity : 10,
    message: {
        status: 429,
        message: "You have sent too many requests, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
})

app.use("/api/auth/get-token", tokenLimiter)
app.use("/api/auth/login", register_login_limit)
app.use("/api/auth/register", register_login_limit)
app.use("/api/auth/logout", register_login_limit)

app.use("/api/auth", (req, res, next) => {
    const bypass = ["/get-token", "/login", "/register", "/logout"]
    if(bypass.some(path => req.originalUrl.startsWith(path))) return next();
    other_auth_limits(req, res, next)
})

app.use("/api", apiLimiter)

app.use(verify_token)

app.use("/api", mainRoutes)

if (process.env.NODE_ENV !== "test") {
    safe_unban_user()
}

app.use(errorMiddleware)

export default app