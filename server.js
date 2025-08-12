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

connectDB()

const app = express()
const PORT = process.env.PORT || 8080

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(helmet())
app.use(helmet.crossOriginResourcePolicy({policy: 'cross-origin'}))
app.use(morgan('common'))
app.use(cors())

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

const authLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: {
        status: 429,
        message: "You have sent too many requests, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
})

app.use("/api/auth", authLimiter)
app.use("/api", apiLimiter)

app.use(verify_token)

app.use("/api", mainRoutes)

safe_unban_user()

app.use(errorMiddleware)

app.listen(PORT, () => {
    console.log(`Server running on por ${PORT}`)
})