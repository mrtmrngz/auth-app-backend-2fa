import express from "express";
import {
    apply_password,
    get_token,
    login,
    logout,
    register_controller,
    resend_otp, sent_reset_password_email_controller,
    verify_otp
} from "../controller/auth.controller.js";


const router = express.Router()

router.post("/register", register_controller)
router.post("/verify-otp", verify_otp)
router.post("/resend-otp", resend_otp)
router.post("/login", login)
router.post("/reset-password-mail", sent_reset_password_email_controller)
router.post("/reset-password-apply", apply_password)
router.get("/get-token", get_token)
router.post("/logout", logout)

export default router