import { RequestHandler } from 'express';
import UserModel from 'src/models/user';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { sendErrorRes } from 'src/utils/helper';
import AuthVerificationTokenModel from 'src/models/authVerificationToken';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET!;
const NODE_MAILER_USER = process.env.NODE_MAILER_USER;
const NODE_MAILER_PASSWORD = process.env.NODE_MAILER_PASSWORD;

export const createNewUser: RequestHandler = async (req, res) => {
  // Read incoming data like: name, email, password
  const { email, password, name } = req.body;

  // Validate if the data is ok or not.
  // Send error if not.
  // if (!name) return sendErrorRes(res, "Name is missing!", 422);
  // if (!email) return sendErrorRes(res, "Email is missing!", 422);
  // if (!password) return sendErrorRes(res, "Password is missing!", 422);

  // 4. Check if we already have account with same user.
  const existingUser = await UserModel.findOne({ email });
  // 5. Send error if yes otherwise create new account and save user inside DB.
  if (existingUser)
    return sendErrorRes(
      res,
      'Unauthorized request, email is already in use!',
      401
    );

  const user = await UserModel.create({ name, email, password });

  // 6. Generate and Store verification token.
  const token = crypto.randomBytes(36).toString('hex');
  await AuthVerificationTokenModel.create({ owner: user._id, token });

  // 7. Send verification link with token to register email.
  const link = `http://localhost:8000/verify.html?id=${user._id}&token=${token}`;

  const transport = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
      user: NODE_MAILER_USER,
      pass: NODE_MAILER_PASSWORD,
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

export const verifyEmail: RequestHandler = async (req, res) => {
  /**
1. Read incoming data like: id and token
2. Find the token inside DB (using owner id).
3. Send error if token not found.
4. Check if the token is valid or not (because we have the encrypted value).
5. If not valid send error otherwise update user is verified.
6. Remove token from database.
7. Send success message.
   **/
  const { id, token } = req.body;

  const authToken = await AuthVerificationTokenModel.findOne({ owner: id });
  if (!authToken) return sendErrorRes(res, 'unauthorized request!', 403);

  const isMatched = await authToken.compareToken(token);
  if (!isMatched)
    return sendErrorRes(res, 'unauthorized request, invalid token!', 403);

  await UserModel.findByIdAndUpdate(id, { verified: true });

  await AuthVerificationTokenModel.findByIdAndDelete(authToken._id);

  res.json({ message: 'Thanks for joining us, your email is verified.' });
};

export const signIn: RequestHandler = async (req, res) => {
  /**
1. Read incoming data like: email and password
2. Find user with the provided email.
3. Send error if user not found.
4. Check if the password is valid or not (because pass is in encrypted form).
5. If not valid send error otherwise generate access & refresh token.
6. Store refresh token inside DB.
7. Send both tokens to user.
    **/

  const { email, password } = req.body;

  const user = await UserModel.findOne({ email });
  if (!user) return sendErrorRes(res, 'Email/Password mismatch!', 403);

  const isMatched = await user.comparePassword(password);
  if (!isMatched) return sendErrorRes(res, 'Email/Password mismatch!', 403);

  const payload = { id: user._id };

  const accessToken = jwt.sign(payload, JWT_SECRET, {
    expiresIn: '15m',
  });
  const refreshToken = jwt.sign(payload, JWT_SECRET);

  if (!user.tokens) user.tokens = [refreshToken];
  else user.tokens.push(refreshToken);

  await user.save();

  res.json({
    profile: {
      id: user._id,
      email: user.email,
      name: user.name,
      verified: user.verified,
    },
    tokens: { refresh: refreshToken, access: accessToken },
  });
};

export const sendProfile: RequestHandler = async (req, res) => {
  res.json({
    profile: req.user,
  });
};
