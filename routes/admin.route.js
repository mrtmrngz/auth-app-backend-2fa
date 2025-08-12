import express from "express";
import {protected_routes} from "../middlewares/protected-routes.js";
import {
    admin_dashboard,
    admin_user_delete,
    admin_user_edit,
    ban_user,
    unban_ban_user
} from "../controller/admin.controller.js";

const router = express.Router()

router.get("/dashboard", protected_routes(["ADMIN"]), admin_dashboard)
router.patch("/ban-user", protected_routes(["ADMIN"]), ban_user)
router.patch("/unban-ban-user", protected_routes(["ADMIN"]), unban_ban_user)
router.patch("/update-user/:id", protected_routes(["ADMIN"]), admin_user_edit)
router.delete("/delete-user/:id", protected_routes(["ADMIN"]), admin_user_delete)

export default router