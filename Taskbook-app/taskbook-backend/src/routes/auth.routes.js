import { Router } from "express"
import { register, verifyUser, resendEmailVerification, login, logout, getUser } from "../controllers/auth.controllers.js"
import validate from "../middlewares/validate.middleware.js"
import { upload } from "../middlewares/multer.middleware.js"
import { loginUserValidators, resendEmailVerificationValidator, userRegistrationValidator } from "../validators/auth.validations.js"
import { isLoggedIn } from "../middlewares/auth.middleware.js"

const router = Router()

router.route("/register").post(userRegistrationValidator(), validate, upload.single('avatar'), register)
router.route("/verify-email/:verificationToken").get(verifyUser)
router.route("resend-verification-email").post(resendEmailVerificationValidator(), validate, resendEmailVerification)
router.route("/login").post(loginUserValidators(), validate, login)
router.route("logout").get(isLoggedIn, logout)

router.route("/get-user").get(isLoggedIn, getUser)

export default router