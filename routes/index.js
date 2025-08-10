import express from "express";
import authRoute from "./auth.route.js";
import userRoute from "./user.route.js";
import {protected_routes} from "../middlewares/protected-routes.js";

const router = express.Router()

router.use("/auth", authRoute)
router.use("/users", userRoute)

export default router