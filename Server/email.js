import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
    service: 'gmail', // or use 'smtp.ethereal.email' for testing
    auth: {
      user: 'testemailoccic@gmail.com',
      pass: 'efoc xfbe benh lijs ', // NOT your regular password; use an App Password or OAuth
    },
  });
  
  // Setup mail options
  const mailOptions = {
    from: 'testemailoccic@gmail.com',
    to: 'storyarkdev@gmail.com',
    subject: 'Your passcode is',
    text: 'Your 2FA code is: 123456',
  };
  
  // Send email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return console.error(error);
    }
    console.log('Email sent:', info.response);
  });