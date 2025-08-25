

const errorMiddleware = async (err, req, res, next) => {
    const logData = {
        message: err.message,
        statusCode: err.statusCode
    }
    console.error(logData)
    const statusCode = err.statusCode || 500
    const message = err.message || "Internal Server error"

    res.status(statusCode).json({
        success: false,
        error: message,
        stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
        ...(err.code && { code: err.code }),
        ...((statusCode === 401 || statusCode === 403) && { isAccess: false })
    })
}

export default errorMiddleware