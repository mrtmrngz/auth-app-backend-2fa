import CustomError from "../helpers/customError.js";


export function protected_routes(roles) {
    return async (req, res, next) => {
        const isAuthenticated  = req.isAuthenticated
        const user = req.user

        if(!user || !isAuthenticated) {
            return next(new CustomError("Unauthorized", 401))
        }

        if(user.role === "admin") {
            return  next()
        }

        if(!roles.includes(user.role)) {
            return next(new CustomError("Forbidden: You are not allowed to access this route.", 403))
        }

        next()
    }
}