
class CustomError extends Error{
    constructor(message=null, statusCode, code) {
        super(message);
        this.statusCode = statusCode
        if(code) this.code = code

        Error.captureStackTrace(this, this.constructor)
    }
}

export default CustomError