import express from "express";
import {register_controller} from "../controller/auth.controller.js";


const router = express.Router()

router.post("/register", register_controller)

export default router