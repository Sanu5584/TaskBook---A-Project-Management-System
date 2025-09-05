import { ApiResponse } from "../utils/api-response.utils.js";
import { asyncHandler } from "../utils/async-handler.utils.js";

const healthCheck = asyncHandler((req, res) => {
    res.status(200).json(
        new ApiResponse(200, "Server was successfully running")
    )
})

export {healthCheck}