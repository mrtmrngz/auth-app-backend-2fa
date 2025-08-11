import express from "express";
import {
    change_mail_or_username, change_other_infos,
    enable_two_factor,
    user_info
} from "../controller/user.controller.js";
import {user_auth_middleware} from "../middlewares/user-auth-middleware.js";
import {upload} from "../libs/upload.js";


const router = express.Router()

router.get('/user-info', user_auth_middleware, user_info)
router.patch('/enable-two-factor', user_auth_middleware, enable_two_factor)
router.patch('/change-mail-or-username', user_auth_middleware, change_mail_or_username)
router.patch('/change-user-infos', user_auth_middleware, upload.single("avatar"), change_other_infos)

export default router