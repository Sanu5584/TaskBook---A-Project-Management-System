import { v2 as cloudinary } from "cloudinary"
import fs from "node:fs"
import { ApiError } from "../utils/api-error.utils.js"
import dotenv from "dotenv"

dotenv.config({
    path: "./.env"
})

cloudinary.config({
    secure: true,
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
})

const uploadOnCloudinary = async function (localFilePath) {

    try {
        // Check if file exists before uploading
        if (!fs.existsSync(localFilePath)) {
            throw new Error(`File not found at path: ${localFilePath}`)
        }

        const response = await cloudinary.uploader
            .upload(localFilePath, {
                resource_type: "auto"
            })

        console.log("cloudinary upload response : ", response);

        // Delete file after successful upload
        fs.unlinkSync(localFilePath)

        return response

    } catch (error) {
        // Try to delete file even if upload failed
        try {
            if (fs.existsSync(localFilePath)) {
                fs.unlinkSync(localFilePath)
            }
        } catch (deleteError) {
            console.error("Failed to delete file: ", deleteError.message)
        }

        console.error("Cloudinary upload error: ", error.message)
        throw new ApiError(500, `Cloudinary upload failed: ${error.message}`)
    }
}

export { uploadOnCloudinary }