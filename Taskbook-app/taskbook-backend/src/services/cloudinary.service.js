import { v2 as cloudinary } from "cloudinary"
import fs from "fs:node"

cloudinary.config({
    secure: true
})

const uploadOnCloudinary = async function (localFilePath) {

    if (!localFilePath) return null

    try {
        const response = await cloudinary.uploader
            .upload(localFilePath, {
                resource_type: "auto"
            });

        fs.unlinkSync(localFilePath)

        console.log("cloudinary upload response : ", response);
    } catch (error) {
        fs.unlinkSync(localFilePath)
        throw new ApiError(500, "Internal Server Error: while uploading on cloudinary")
    }
}

export { uploadOnCloudinary }