

const errorMiddleware = async (err, req, res, next) => {
    console.error(err)
    const statusCode = err.statusCode || 500
    const message = err.message || "Internal Server error"

    res.status(statusCode).json({
        success: false,
        error: message,
        stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
        ...((statusCode === 401 || statusCode === 403) && { isAccess: false })
    })
}

export default errorMiddleware