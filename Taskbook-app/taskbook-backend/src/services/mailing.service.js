import nodemailer from "nodemailer"
import Mailgen from "mailgen"

import { ApiError } from "../utils/api-error.utils.js"

const sendMail = async ({ email, subject, mailgenContent }) => {

    const mailGenerator = new Mailgen({
        theme: 'default',
        product: {
            name: "Taskbook app",
            link: "https://github.com/Sanu5584/TaskBook---A-Project-Management-System",
            logo: "./assets/Taskbook-logo.png",
        }
    })

    const textualEmail = mailGenerator.generatePlaintext(mailgenContent)

    const emailHtml = mailGenerator.generate(mailgenContent)

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
        from: process.env.SMTP_MAILTRAP_USER,
        to: email,
        subject: subject,
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

const emailVerificationMailgenContent = (user, verificationUrl) => {
    return {
        body: {
            name: user,
            intro: 'Welcome to Taskbook! We\'re very excited to have you on board.',
            action: {
                instructions: 'The link will be expired in next 10 mins, please click here:',
                button: {
                    color: '#22BC66', // Optional action button color
                    text: 'Verify your account',
                    link: verificationUrl
                }
            },
            outro: 'This email is automated, so don\'t reply, if you need any help feel free to contact our customer support'
        }

    }
}

const forgotPasswordRequestMailGenContent = (user, verificationUrl) => {
    return {
        body: {
            name: user,
            intro: "Welcome to Taskbook! we are happy to solve your quries",
            action: {
                instructions: "The link will be expired in next 10 mins, please click the here to add new password",
                button: {
                    color: '#22BC66', // Optional action button color
                    text: 'Replace new Password',
                    link: verificationUrl
                },
            },
            outro: 'This email is automated, so don\'t reply, if you need any help feel free to contact our customer support'
        }
    }
}

export { sendMail, emailVerificationMailgenContent, forgotPasswordRequestMailGenContent }