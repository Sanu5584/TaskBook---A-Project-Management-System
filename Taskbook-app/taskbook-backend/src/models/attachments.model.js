import mongoose, { Schema } from "mongoose"

const attachments = new Schema(
    {
        attachments: {
            type: [
                {
                    url: String,
                    mimeType: String,
                    publicId: String,
                    size: Number
                }
            ],
        },
        project: {
            type: Schema.Types.ObjectId,
            ref: "Project",
            required: true
        },
        task: {
            type: Schema.Types.ObjectId,
            ref: "Task",
            required: true
        },
        uploadedBy: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        }
    },
    {
        timestamps: true
    }
)

const Attachments = mongoose.model("Attachments", attachments)

export default Attachments