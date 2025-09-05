import nodemailer from "nodemailer"
import Mailgen from "mailgen"

import { ApiError } from "../utils/api-error.utils.js"

const sendMail = async (options) => {

    const mailGenerator = new Mailgen({
        theme: 'cerberus',
        product: {
            name: "Taskbook app",
            link: "https://github.com/Sanu5584/TaskBook---A-Project-Management-System",
            logo: "../../public/Taskbook-logo.png",
        }
    })

    const textualEmail = mailGenerator.generatePlainText(options.mailgenContent)

    const emailHtml = mailGenerator.generate(options.mailgenContent)

    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_MAILTRAP_HOST,
        port: process.env.SMTP_MAILTRAP_PORT,
        secure: false,
        auth: {
            user: process.env.SMTP_MAILTRAP_USER,
            pass: process.env.SMTP_MAILTRAP_PASSWORD
        }
    })

    const emailInfo = {
        from: process.env.SMTP_MAILTRAP_USERNAME,
        to: username,
        subject: options.subject,
        text: textualEmail,
        html: emailHtml
    }

    try {
        await transporter.sendMail(emailInfo)
    } catch (error) {
        console.error("Error occured white sending the email : ", error);
        throw new ApiError(400, "Failed to send the email", error)
    }
}

export { sendMail }