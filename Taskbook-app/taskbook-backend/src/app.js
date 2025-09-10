import express from "express";
import cookieParser from "cookie-parser";

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

// Import all routes here
import healthCheckRoutes from "./routes/healthCheck.routes.js"
import authRoutes from "./routes/auth.routes.js"
import cookieParser from "cookie-parser";

app.use("api/v1/healthcheck", healthCheckRoutes)
app.use("api/v1/auth/", authRoutes)

export default app