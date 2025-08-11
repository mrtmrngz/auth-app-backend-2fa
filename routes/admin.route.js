import express from "express";
import {protected_routes} from "../middlewares/protected-routes.js";
import {admin_dashboard, ban_user, unban_ban_user} from "../controller/admin.controller.js";

const router = express.Router()

router.get("/dashboard", protected_routes(["ADMIN"]), admin_dashboard)
router.patch("/ban-user", protected_routes(["ADMIN"]), ban_user)
router.patch("/unban-ban-user", protected_routes(["ADMIN"]), unban_ban_user)

export default router