import express from "express";
import {register_controller, resend_otp, verify_account} from "../controller/auth.controller.js";


const router = express.Router()

router.post("/register", register_controller)
router.post("/verify-account", verify_account)
router.post("/resend-otp", resend_otp)

export default router