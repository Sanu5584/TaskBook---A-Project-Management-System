import dotenv from "dotenv"

import app from "./app.js"
import dbConnect from "./db/dbConnect.js"

dotenv.config({
    path: "./.env"
})

const PORT = process.env.PORT || 8000

dbConnect()
    .then(() => {
        app.listen(PORT, () => console.log(`Server is running on port : ${PORT}`))
    })
    .catch((error) => {
        console.error("MongoDB connection failed", error);
        process.exit(1)
    })