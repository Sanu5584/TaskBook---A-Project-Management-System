import multer from "multer"
import { avatarMimetype } from "../utils/constants.utils.js"
import { ApiError } from "../utils/api-error.utils.js"
import { asyncHandler } from "../utils/async-handler.utils.js"

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "../../public/images")
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, `${file.fieldname} - ${uniqueSuffix}`)
    }
})

const limits = {
    fileSize: 10 * 1024 * 1024
}

const fileFilter = function (req, file, cb) {
    if (avatarMimetype.includes(file.mimetype)) {
        cb(null, true)
    } else {
        cb(new ApiError(400, "Invalid extension/mimetype, please provide jpeg, webp, avif, png files only"))
    }
}

const uploadedFile = multer({
    storage,
    limits,
    fileFilter
})

// multer error handler
const singleFileHandler = (fieldname) => {
    return asyncHandler((req, res, next) => {
        const upload = uploadedFile.single(fieldname)
        upload(req, res, function (err) {
            if (err instanceof multer.MulterError) {
                switch (err.code) {
                    case "LIMIT_FILE_SIZE":
                        throw new ApiError(400, "MulterError: file is too large, it should be less than 10mb")
                    case "LIMIT_FILE_COUNT":
                        throw new ApiError(400, "MulterError: too many files, there should be only one avatar file")
                    case "LIMIT_UNEXPECTED_FILE":
                        throw new ApiError(400, "MulterError: unexpected field")
                    case "MISSING_FIELD_NAME":
                        throw new ApiError(400, "MulterError: field name missing")
                    default:
                        throw new ApiError(400, `MulterError: ${err.message} & ${err.cause} & ${err}`)
                }
            }
            else if (err) {
                throw new ApiError(500, "An unexpected error occurs while uploading the file: ", err)
            }
            else {
                next()
            }
        })
    })
}

const upload = {
    single: singleFileHandler
}

export { upload }