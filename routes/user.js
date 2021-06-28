const express = require("express");
const router = express.Router();
const catchAsync = require("../utils/catchAsync");
const passport = require("passport");
const { isLoggedIn } = require("../middleware.js");
const users = require("../controllers/users");

router
  .route("/register")
  .get(users.renderRegister)
  .post(catchAsync(users.register));

router
  .route("/login")
  .get(users.renderLogin)
  .post(
    passport.authenticate("local", {
      failureFlash: true,
      failureRedirect: "/login",
    }),
    catchAsync(users.login)
  );

router.get("/userDetails/:id", isLoggedIn, catchAsync(users.renderUserDetails));

router.get("/forgotPassword", users.renderForgotPassword);

router.post("/forgotPassword/email", users.emailVerification);

router
  .route("/reset/:token/email")
  .get(users.renderToken)
  .post(users.changePassword);

router.post("/forgotPassword/sms", users.smsVerification);

router
  .route("/reset/:token/sms")
  .get(users.renderSMSToken)
  .post(users.changePasswordBySMS);

router.get("/logout", users.logout);

module.exports = router;
