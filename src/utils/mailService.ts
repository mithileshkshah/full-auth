import nodemailer from "nodemailer";

export const sendMail = async (
  to: string,
  subject: string,
  html: string,
  text?: string
) => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST, // e.g. smtp.gmail.com
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false, // true for port 465, false for 587
    auth: {
      user: process.env.SMTP_USER, // your email
      pass: process.env.SMTP_PASS, // your app password
    },
  });

  const mailOptions = {
    from: `"Full Auth Implementation" <${process.env.SMTP_USER}>`,
    to,
    subject,
    html,
    text,
  };

  return transporter.sendMail(mailOptions);
};
