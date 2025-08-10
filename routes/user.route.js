import express from "express";
import {enable_two_factor, user_info} from "../controller/user.controller.js";
import {user_auth_middleware} from "../middlewares/user-auth-middleware.js";


const router = express.Router()

router.get('/user-info', user_auth_middleware, user_info)
router.patch('/enable-two-factor', user_auth_middleware, enable_two_factor)

export default router