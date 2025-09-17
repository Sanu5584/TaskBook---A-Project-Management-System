import { Router } from "express"

import { register, verifyUser, resendEmailVerification, login, logout, changeCurrentPassword, forgotPasswordRequest, resetForgottenPassword, getUser, refreshAccessToken } from "../controllers/auth.controllers.js"
import validate from "../middlewares/validate.middleware.js"
import { upload } from "../middlewares/multer.middleware.js"
import { changeCurrentPasswordValidators, forgotPasswordRequestValidator, loginUserValidators, resendEmailVerificationValidator, resetForgottenPasswordValidator, userRegistrationValidator } from "../validators/auth.validations.js"
import { isLoggedIn } from "../middlewares/auth.middleware.js"

const router = Router()

router.route("/register").post(upload.single('avatar'), userRegistrationValidator(), validate, register)

router.route("/verify-email/:verificationToken").get(verifyUser)

router.route("/resend-verification-email").post(resendEmailVerificationValidator(), validate, resendEmailVerification)

router.route("/login").post(loginUserValidators(), validate, login)

router.route("/logout").get(isLoggedIn, logout)

router.route("/change-current-password").post(isLoggedIn, changeCurrentPasswordValidators(), validate, changeCurrentPassword)

router.route("/forgot-password-request").post(forgotPasswordRequestValidator(), validate, forgotPasswordRequest)

router.route("/reset-forgotten-password/:forgotPasswordToken").post(resetForgottenPasswordValidator(), validate, resetForgottenPassword)

router.route("/refresh-token").post(refreshAccessToken)

router.route("/get-user").get(isLoggedIn, getUser)

export default router