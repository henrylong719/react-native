import { RequestHandler } from 'express';
import UserModel from 'src/models/user';
import crypto from 'crypto';
import { sendErrorRes } from 'src/utils/helper';
import AuthVerificationTokenModel from 'src/models/authVerificationToken';
import jwt from 'jsonwebtoken';
import mail from 'src/utils/main';

const VERIFICATION_LINK = process.env.VERIFICATION_LINK;
const JWT_SECRET = process.env.JWT_SECRET!;

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
  const link = `${VERIFICATION_LINK}?id=${user._id}&token=${token}`;

  // const transport = nodemailer.createTransport({
  //   host: "sandbox.smtp.mailtrap.io",
  //   port: 2525,
  //   auth: {
  //     user: "c5cf93b6836166",
  //     pass: "081dde13a955c9",
  //   },
  // });

  // await transport.sendMail({
  //   from: "verification@myapp.com",
  //   to: user.email,
  //   html: `<h1>Please click on <a href="${link}">this link</a> to verify your account.</h1>`,
  // });

  await mail.sendVerification(user.email, link);

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

export const generateVerificationLink: RequestHandler = async (req, res) => {
  /**
1. check if user is authenticated or not
2. remove previous token if any
3. create/store new token and 
4. send link inside users email
5. send response back
   **/
  const { id } = req.user;
  const token = crypto.randomBytes(36).toString('hex');

  const link = `${VERIFICATION_LINK}?id=${id}&token=${token}`;

  await AuthVerificationTokenModel.findOneAndDelete({ owner: id });

  await AuthVerificationTokenModel.create({ owner: id, token });

  await mail.sendVerification(req.user.email, link);

  res.json({ message: 'Please check your inbox.' });
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

export const grantAccessToken: RequestHandler = async (req, res) => {
  /**
1. Read and verify refresh token
2. Find user with payload.id and refresh token
3. If the refresh token is valid and no user found, token is compromised.
4. Remove all the previous tokens and send error response.
5. If the the token is valid and user found create new refresh and access token.
6. Remove previous token, update user and send new tokens.  
  **/

  const { refreshToken } = req.body;

  if (!refreshToken) return sendErrorRes(res, 'Unauthorized request!', 403);

  const payload = jwt.verify(refreshToken, JWT_SECRET) as { id: string };

  if (!payload.id) return sendErrorRes(res, 'Unauthorized request!', 401);

  const user = await UserModel.findOne({
    _id: payload.id,
    tokens: refreshToken,
  });

  if (!user) {
    // user is compromised, remove all the previous tokens
    await UserModel.findByIdAndUpdate(payload.id, { tokens: [] });
    return sendErrorRes(res, 'Unauthorized request!', 401);
  }

  const newAccessToken = jwt.sign({ id: user._id }, JWT_SECRET, {
    expiresIn: '15m',
  });
  const newRefreshToken = jwt.sign({ id: user._id }, JWT_SECRET);

  const filteredTokens = user.tokens.filter((t) => t !== refreshToken);
  user.tokens = filteredTokens;
  user.tokens.push(newRefreshToken);
  await user.save();

  res.json({
    tokens: { refresh: newRefreshToken, access: newAccessToken },
  });
};

export const sendProfile: RequestHandler = async (req, res) => {
  res.json({
    profile: req.user,
  });
};
