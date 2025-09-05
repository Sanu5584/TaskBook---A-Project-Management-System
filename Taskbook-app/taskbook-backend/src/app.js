import express from "express";

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// Import all routes here
import healthCheckRoutes from "./routes/healthCheck.routes.js"
import authRoutes from "./routes/auth.routes.js"

app.use("api/v1/healthcheck", healthCheckRoutes)
app.use("api/v1/auth/", authRoutes)

export default app