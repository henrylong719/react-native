import { RequestHandler } from 'express';
import UserModel from 'src/models/user';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import AuthVerificationTokenModel from 'src/models/authVerificationToken';

export const createNewUser: RequestHandler = async (req, res): Promise<any> => {
  // Read incoming data like: name, email, password
  const { email, password, name } = req.body;

  // Validate if the data is ok or not.
  // Send error if not.
  if (!name) return res.status(422).json({ message: 'Name is missing!' });
  if (!email) return res.status(422).json({ message: 'Email is missing!' });
  if (!password)
    return res.status(422).json({ message: 'Password is missing!' });

  // 4. Check if we already have account with same user.
  const existingUser = await UserModel.findOne({ email });
  // 5. Send error if yes otherwise create new account and save user inside DB.
  if (existingUser)
    return res
      .status(401)
      .json({ message: 'Unauthorized request, email is already in use!' });

  const user = await UserModel.create({ name, email, password });

  // 6. Generate and Store verification token.
  const token = crypto.randomBytes(36).toString('hex');
  await AuthVerificationTokenModel.create({ owner: user._id, token });

  // 7. Send verification link with token to register email.
  const link = `http://localhost:8000/verify?id=${user._id}&token=${token}`;

  // Looking to send emails in production? Check out our Email API/SMTP product!
  var transport = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
      user: 'ebe3af1fb1b612',
      pass: '2b4909b33c6f12',
    },
  });

  await transport.sendMail({
    from: 'verification@myapp.com',
    to: user.email,
    html: `<h1>Please click on <a href="${link}">this link</a> to verify your account.</h1>`,
  });

  // 8. Send message back to check email inbox.
  res.json({ message: 'Please check your inbox.' });
};
