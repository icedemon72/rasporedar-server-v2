import {
  checkAccessToken,
  refreshAccessToken,
  decodeAccess,
  setSessionFalse,
  loginUser,
  logout
} from '../services/sessionService.js';
import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';

export const authenticateUser = async (req, res, next) => {
  try {
    const refreshToken = req.cookies['refresh_token'] || req.body.refresh_token;
    let accessToken = req.cookies.access_token;
    if (!accessToken) {
      return res.status(403).send({ message: 'No access token!' });
    }

    const userAgent = req.headers['user-agent'];
    const accessStatus = checkAccessToken(accessToken);
    if (accessStatus === 0) {
      throw { status: 403, message: 'Invalid access token' };
    }

    if (accessStatus === 2) {
      if (!refreshToken) {
        return res.status(401).send({ message: 'Refresh token missing!' });
      }

      const newTokens = await refreshAccessToken(refreshToken, userAgent);
      if (!newTokens) {
        return res.status(401).send({ message: 'Invalid refresh token' });
      }

      res.cookie("access_token", newTokens.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 15 * 60 * 1000,
      });

      return res.status(200).send({
        access_token: newTokens.access_token,
        message: 'Access token refreshed',
      });
    }

    req.userTokenData = decodeAccess(accessToken);
    next();
  } catch (err) {
    const refreshToken = req.cookies['refresh_token'];
    const userAgent = req.headers['user-agent'];
    await setSessionFalse(refreshToken, userAgent);
    return res.status(err.status || 500).send({ message: err.message });
  }
};

export const authorizeUser = (req, res, next) => {
  try {
    const data = req.userTokenData;
    if (data.role === 'Admin' || data.role === 'Moderator') {
      return next();
    } else {
      return res.status(403).send({ message: 'Access not allowed!' });
    }
  } catch {
    return res.status(403).send({ message: 'Access not allowed!' });
  }
};

export const checkRole = (req, res) => {
  try {
    if (!req.userTokenData) {
      return res.status(403).send({ message: 'Niste ulogovani!' });
    }
    return res.status(200).send({ role: req.userTokenData.role });
  } catch {
    return res.status(500).send({ message: 'Internal server error!' });
  }
};

export const handleLoginUser = async (req, res) => {
  try {
    if (req.userTokenData) {
      return res.status(401).send({ message: 'Već ste ulogovani' });
    }

    const userAgent = req.headers['user-agent'];
    const { email, password } = req.body;

    const session = await loginUser(email, password, userAgent);

    res.cookie("access_token", session.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("refresh_token", session.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).send({
      user: session.user,
      message: 'Logged in successfully',
    });
  } catch (err) {
    return res.status(err.status || 500).send({ message: err.message });
  }
};

export const handleLogout = async (req, res) => {
  try {
    const refreshToken = req.cookies['refresh_token'];
    const userAgent = req.headers['user-agent'];

    if (!refreshToken) {
      return res.status(403).send({ message: 'Niste ulogovani!' });
    }

    await logout(refreshToken, userAgent);

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
    });
    
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
    });

    return res.status(200).send({ message: 'Logged out successfully' });
  } catch (err) {
    return res.status(err.status || 500).send({ message: err.message });
  }
};

export const handleRefresh = async (req, res) => {
  try {
    const refreshToken = req.cookies['refresh_token'] || req.body.refresh_token;
    const userAgent = req.headers['user-agent'];

    if (!refreshToken) {
      return res.status(401).send({ message: 'Refresh token is required' });
    }

    const tokens = await refreshAccessToken(refreshToken, userAgent);
    if (!tokens) {
      return res.status(403).send({ message: 'Invalid refresh token' });
    }

    res.cookie("access_token", tokens.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 15 * 60 * 1000,
    });

    return res.status(200).send({
      access_token: tokens.access_token,
      message: 'Token refreshed',
    });
  } catch (err) {
    return res.status(err.status || 500).send({ message: err.message });
  }
};

export const checkValidAccess = (req, res) => {
  const accessToken = req.cookies['access_token'];

  if (!req.userTokenData || !accessToken) {
    return res.status(403).send({ message: 'Not authorized' });
  }

  if (checkAccessToken(accessToken) === 1) {
    return res.status(200).send({ message: 'All good!' });
  }

  return res.status(401).send({ message: 'Not authenticated...' });
};

export const getUserFromSession = async (req, res) => {
  try {
    const accessToken = req.cookies.access_token;
    if (!accessToken) {
      return res.status(401).json({ message: "Access token not found" });
    }

    let decoded;
    try {
      decoded = jwt.verify(accessToken, process.env.AUTH_ACCESS_TOKEN_SECRET);
    } catch (err) {
      if (err.message === "jwt expired") {
        return res.status(401).json({ message: "Access token expired" });
      }
      return res.status(401).json({ message: "Invalid access token" });
    }

    const user = await User.findById(decoded._id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Me endpoint error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};