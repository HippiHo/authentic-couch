require("dotenv").config({ path: "./.env" });
const nodemailer = require("nodemailer");
const port = process.env.PORT || 8080;

module.exports = sendVerificationEmail = async (
  req,
  res,
  verificationToken
) => {
  return new Promise((resolve, reject) => {
    const config = {
      host: process.env.MAILHOST,
      port: process.env.MAIL_PORT,
      secure: false,
      auth: {
        user: process.env.MAILUSER,
        pass: process.env.MAILPW
      }
    };
    let transporter = nodemailer.createTransport(config);
    let verificationLink = `http://localhost:${port}/api/verify/${verificationToken}`;
    let text = `Hey "${
      req.body.name
    }", thanks for registering with Authentic-couch. <a href="${verificationLink}">Verify your account</a>`;

    let mailOptions = {
      from: `"Authentic-couch" <info@authntic-couch.org>`,
      to: process.env.MAILRECEIVER,
      subject: "Registration complete",
      text: text,
      html: text
    };
    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        reject({ success: false, error: error });
      }
      resolve({ success: true, verificationLink: verificationLink });
    });
  });
};
