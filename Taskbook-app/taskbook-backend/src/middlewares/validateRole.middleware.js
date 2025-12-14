import { asyncHandler } from "../utils/async-handler.utils.js";
import { ApiError } from "../utils/api-error.utils.js";
import { validatePermission } from "../utils/permissions.utils.js";


const hasPermission = (permission) => {
    // get the access permit action of features from the middleware
    return asyncHandler(async (req, res, next) => {
        // get the user id from the req object
        const userId = req?.user._id

        // get the projectId from the params
        const { projectId } = req.params

        // validate the userId and projectId
        if (!userId || !projectId) {
            throw new ApiError(400, "Missing User or Project Id")
        }

        // run accessPermit function to validate the permission was relates to the user's and it's role
        const isAccessible = await validatePermission(permission, userId, projectId)

        // if not accessable then throw error
        if (!isAccessible) {
            throw new ApiError(401, "Unauthorized Access")
        }
        // else run next() function
        next()
    })
}


export { hasPermission }

// const checkAdmin = asyncHandler(async (req, res, next) => {
//     // get the user from the req object
//     const userId = req.user._id

//     // validate the user
//     if (!userId || userId === null || userId === undefined || mongoose.Types.ObjectId.isValid(userId) === false) {
//         throw new ApiError(400, "User Id is invalid or unauthorized request")
//     }

//     // get the user data
//     const user = await User.findById(userId)

//     if (!user) {
//         throw new ApiError(404, "User not found")
//     }

//     // validate the role from the constants
//     if (!AvailableUserRoles.includes(user.role)) {
//         throw new ApiError(400, "Not verified role")
//     }

//     // validate the role from the db
//     if (user.role === UserRolesEnum.ADMIN) {
//         next()
//     } else {
//         throw new ApiError(403, "Admin access only")
//     }
// })