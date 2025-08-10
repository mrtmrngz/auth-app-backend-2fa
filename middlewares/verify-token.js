import jwt from "jsonwebtoken";

export const verify_token = async (req, res, next) => {

    const authHeaders = req.headers["authorization"]

    const token = authHeaders && authHeaders.split(" ")[1]

    if (!token) {
        req.isAuthenticated = false
        return next()
    }


    jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err, payload) => {
        if (err) {
            req.user = null
            req.isAuthenticated = false
            return next()
        }

        req.user = { id: payload.id, role: payload.role }
        req.isAuthenticated = true
        next()
    })

}