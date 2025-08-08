import express from "express";
import {
    get_token,
    login,
    logout,
    register_controller,
    resend_otp,
    verify_account
} from "../controller/auth.controller.js";


const router = express.Router()

router.post("/register", register_controller)
router.post("/verify-account", verify_account)
router.post("/resend-otp", resend_otp)
router.post("/login", login)
router.post("/logout", logout)
router.post("/get-token", get_token)

export default router