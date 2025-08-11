import express from "express";
import authRoute from "./auth.route.js";
import userRoute from "./user.route.js";
import adminRoute from "./admin.route.js";

const router = express.Router()

router.use("/auth", authRoute)
router.use("/users", userRoute)
router.use("/admin", adminRoute)

export default router