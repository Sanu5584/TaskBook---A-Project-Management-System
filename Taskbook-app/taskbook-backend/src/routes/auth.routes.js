import { Router } from "express"
import { register } from "../controllers/auth.controllers.js"
import validate from "../middlewares/validate.middleware.js"
import { upload } from "../middlewares/multer.middleware.js"
import { userRegistrationValidator } from "../validators/auth.validations.js"

const router = Router()

router.route("/register").post(userRegistrationValidator(), validate, upload.single('avatar'), register)

export default router