import CustomError from "../helpers/customError.js";


export const user_auth_middleware = async (req, res, next) => {
    if(req.isAuthenticated && req.user) {
        next()
    }else {
        return next(new CustomError("Unauthorized!", 401))
    }
}