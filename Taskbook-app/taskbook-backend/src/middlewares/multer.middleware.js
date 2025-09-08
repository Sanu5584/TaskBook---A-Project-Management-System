import multer from "multer"
import { ApiError } from "../utils/api-error.utils"
import { AvailableMimeTypes } from "../utils/constants.utils.js"

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public', './public/images')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9)
        cb(null, `${file.originalname}-${uniqueSuffix}`)
    }
})

const upload = multer({
    storage,
    limits: {
        fileSize: 1 * 1000 * 1000
    },
    fileFilter: function (req, file, cb) {
        if (AvailableMimeTypes.includes(file.mimetype)) {
            cb(null, true)
        } else {
            throw new ApiError(415, "Unsupported media type")
        }
    }
})