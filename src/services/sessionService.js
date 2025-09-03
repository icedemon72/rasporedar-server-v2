import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Session from './../models/sessionModel.js';
import User from './../models/userModel.js';

export const checkRefreshToken = (refreshToken) => {
  return jwt.verify(refreshToken, process.env.AUTH_REFRESH_TOKEN_SECRET, (err) => {
    return err === null;
  });
};

export const checkAccessToken = (accessToken) => {
  return jwt.verify(accessToken, process.env.AUTH_ACCESS_TOKEN_SECRET, (err) => {
    if (err) {
      return (err.message === 'jwt expired') ? 2 : 0;
    }
    return 1;
  });
};

export const decodeAccess = (accessToken) => {
  return jwt.decode(accessToken);
};

export const refreshAccessToken = async (refreshToken, userAgent) => {
  const session = await Session.findOne({ refreshToken, active: true });
  if (!session) return null;

  let userId;
  try {
    const decoded = jwt.verify(refreshToken, process.env.AUTH_REFRESH_TOKEN_SECRET);
    userId = decoded._id;
  } catch (err) {
    return null;
  }

  const user = await User.findById(userId);
  if (!user) return null;

  const userData = {
    _id: user._id.toString(),
    email: user.email,
    name: user.name,
    username: user.username,
    role: user.role,
  };

  const newAccessToken = jwt.sign(userData, process.env.AUTH_ACCESS_TOKEN_SECRET, {
    expiresIn: process.env.AUTH_ACCESS_TOKEN_EXPIRY || "1d",
  });

  return {
    access_token: newAccessToken,
    user: userData,
  };
};

export const loginUser = async (email, password, userAgent) => {
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) throw { status: 400, message: 'Invalid email or password' };

  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if (!isPasswordCorrect) throw { status: 400, message: 'Invalid email or password' };

  // Deactivate existing session
  const existingSession = await Session.findOne({ user: user._id, active: true });
  if (existingSession) {
    existingSession.active = false;
    await existingSession.save();
  }

  const userData = {
    _id: user._id.toString(),
    email: user.email,
    name: user.name,
    username: user.username,
    role: user.role,
  };

  const accessToken = jwt.sign(userData, process.env.AUTH_ACCESS_TOKEN_SECRET, {
    expiresIn: process.env.AUTH_ACCESS_TOKEN_EXPIRY || "1d",
  });

  const refreshToken = jwt.sign({ _id: user._id }, process.env.AUTH_REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.AUTH_REFRESH_TOKEN_EXPIRY || "7d",
  });

  const session = new Session({
    user: user._id,
    refreshToken,
    active: true,
    userAgent,
  });
  await session.save();

  return {
    accessToken,
    refreshToken,
    user: {
      id: user._id.toString(),
      email: user.email,
      name: user.name,
    },
  };
};

export const logout = async (refreshToken, userAgent) => {
  const session = await Session.findOne({ refreshToken, active: true });
  if (session) {
    session.active = false;
    await session.save();
  }
};

export const setSessionFalse = async (refreshToken, userAgent) => {
  const session = await Session.findOne({ refreshToken, userAgent, active: true });
  if (session) {
    session.active = false;
    await session.save();
    return true;
  }
  return false;
};