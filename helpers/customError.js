
class CustomError extends Error{
    constructor(message=null, statusCode) {
        super(message);
        this.statusCode = statusCode

        Error.captureStackTrace(this, this.constructor)
    }
}

export default CustomError