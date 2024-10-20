const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;

    // Check if the token exists in the cookies
    if (!token) {
      return res.status(401).json({ message: "Not authorized, please login" });
    }

    // Verify Token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // Get user id from the verified token
    const user = await User.findById(verified.id).select("-password");

    // Check if user exists
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // Attach user object to the request object
    req.user = user;

    // Proceed to the next middleware/route
    next();
  } catch (error) {
    // Handle errors (e.g., invalid token, expired token)
    return res.status(401).json({ message: "Session expired, please login again" });
  }
});

module.exports = protect;
