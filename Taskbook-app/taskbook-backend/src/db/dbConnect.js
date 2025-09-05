import mongoose from "mongoose"

const dbConnect = async function(){
    try {
        mongoose.connect(process.env.MONGO_URI)
        console.log("MongoDB connected successfully");
    } catch (error) {
        console.error("MongoDB connection failed",error)
        process.exit(1)
    }
}

export default dbConnect