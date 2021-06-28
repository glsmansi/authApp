var async = require("async");
var nodemailer = require("nodemailer");
var crypto = require("crypto");
var twilio = require("twilio");
const port = process.env.POST || 3000;
var ip = require("ip");
const User = require("../models/User");
const dotenv = require("dotenv");
dotenv.config();
var accountSid = process.env.ACCOUNT_SID;
var authToken = process.env.AUTH_TOKEN;
var pass = process.env.USER_PASSWORD;
var twilioPhno = process.env.TWILIO_PHNO;
var emailID = process.env.USER_EMAILID;

module.exports.renderRegister = (req, res) => {
  res.render("users/register");
};

module.exports.register = async (req, res) => {
  try {
    console.log(req.body);
    const { fname, lname, username, email, phno, password } = req.body;
    const user = new User({ fname, lname, username, email, phno });
    const registeredUser = await User.register(user, password);
    req.login(registeredUser, (err) => {
      if (err) return next();
      req.flash("success", "Welcome to AuthApp");
      res.redirect("/");
    });
  } catch (e) {
    console.log(e);
    req.flash("error", e.message);
    res.redirect("/register");
  }
};

module.exports.renderLogin = (req, res) => {
  res.render("users/login");
};

module.exports.login = async (req, res) => {
  req.flash("success", "Welcome back");
  res.redirect("/");
};

module.exports.renderUserDetails = async (req, res) => {
  const user = await User.findById(req.params.id);
  res.render("users/userDetails", { user });
};

module.exports.renderForgotPassword = (req, res) => {
  res.render("users/forgotPassword");
};

module.exports.emailVerification = function (req, res, next) {
  async.waterfall(
    [
      //functions are first class objects, can pass the values around
      function (done) {
        crypto.randomBytes(20, function (err, buf) {
          var token = buf.toString("hex");
          done(err, token);
        });
      },
      function (token, done) {
        User.findOne({ email: req.body.email }, function (err, user) {
          if (!user) {
            req.flash("error", "No account with that email address exists.");
            return res.redirect("/forgotPassword");
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

          user.save(function (err) {
            done(err, token, user);
          });
        });
      },
      function (token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: emailID,
            pass: pass,
          },
        });
        var mailOptions = {
          to: user.email,
          from: emailID,
          subject: "Node.js Password Reset",
          text:
            "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
            "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
            "http://" +
            req.headers.host +
            "/reset/" +
            token +
            "/email" +
            "\n\n" +
            "If you did not request this, please ignore this email and your password will remain unchanged.\n",
        };
        smtpTransport.sendMail(mailOptions, function (err) {
          console.log("mail sent");
          req.flash(
            "success",
            "An e-mail has been sent to " +
              user.email +
              " with further instructions."
          );
          done(err, "done");
        });
      },
    ],
    function (err) {
      if (err) return next(err);
      res.redirect("/forgotPassword");
    }
  );
};

module.exports.renderToken = function (req, res) {
  User.findOne(
    {
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    },
    function (err, user) {
      if (!user) {
        req.flash("error", "Password reset token is invalid or has expired.");
        return res.redirect("/forgotPassword");
      }
      res.render("users/resetByEmail", { token: req.params.token });
    }
  );
};

module.exports.changePassword = function (req, res) {
  async.waterfall(
    [
      function (done) {
        User.findOne(
          {
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
          },
          function (err, user) {
            if (!user) {
              req.flash(
                "error",
                "Password reset token is invalid or has expired."
              );
              return res.redirect("/forgotPassword");
            }
            if (req.body.password === req.body.confirm) {
              user.setPassword(req.body.password, function (err) {
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save(function (err) {
                  req.logIn(user, function (err) {
                    done(err, user);
                  });
                });
              });
            } else {
              req.flash("error", "Passwords do not match.");
              return res.redirect("back");
            }
          }
        );
      },
      function (user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: emailID,
            pass: pass,
          },
        });
        var mailOptions = {
          to: user.email,
          from: emailID,
          subject: "Your password has been changed",
          text:
            "Hello,\n\n" +
            "This is a confirmation that the password for your account " +
            user.email +
            " has just been changed.\n",
        };
        smtpTransport.sendMail(mailOptions, function (err) {
          req.flash("success", "Success! Your password has been changed.");
          done(err);
        });
      },
    ],
    function (err) {
      res.redirect("/");
    }
  );
};

module.exports.smsVerification = async (req, res) => {
  async.waterfall([
    function (done) {
      crypto.randomBytes(20, function (err, buf) {
        var token = buf.toString("hex");
        done(err, token);
      });
    },

    function (token, done) {
      User.findOne(
        { username: req.body.username, phno: req.body.phno },
        function (err, user) {
          if (!user) {
            req.flash(
              "error",
              "No account with that username and phone number exists."
            );
            return res.redirect("/forgotPassword");
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

          user.save(function (err) {
            done(err, token, user);
          });
        }
      );
    },

    function (token, user) {
      var client = new twilio(accountSid, authToken);

      client.messages
        .create({
          body:
            "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
            "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
            "http://" +
            ip.address() +
            ":" +
            port +
            "/reset/" +
            token +
            "/sms" +
            "\n\n" +
            "If you did not request this, please ignore this sms and your password will remain unchanged.\n",
          to: `+91${user.phno}`, // Text this number
          from: twilioPhno, // From a valid Twilio number
        })
        .then(() => {
          req.flash(
            "success",
            " SMS has been sent to " + user.phno + " with further instructions."
          );
          res.redirect("/");
        })
        .catch((err) => {
          req.flash("error", err.message);
          res.redirect("/forgotPassword");
        });
    },
  ]);
};

module.exports.renderSMSToken = function (req, res) {
  User.findOne(
    {
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    },
    function (err, user) {
      if (!user) {
        req.flash("error", "Password reset token is invalid or has expired.");
        return res.redirect("/forgotPassword");
      }
      res.render("users/resetBySMS", { token: req.params.token });
    }
  );
};

module.exports.changePasswordBySMS = function (req, res) {
  async.waterfall([
    function (done) {
      User.findOne(
        {
          resetPasswordToken: req.params.token,
          resetPasswordExpires: { $gt: Date.now() },
        },
        function (err, user) {
          if (!user) {
            req.flash(
              "error",
              "Password reset token is invalid or has expired."
            );
            return res.redirect("/forgotPassword");
          }
          if (req.body.password === req.body.confirm) {
            user.setPassword(req.body.password, function (err) {
              user.resetPasswordToken = undefined;
              user.resetPasswordExpires = undefined;

              user.save(function (err) {
                req.logIn(user, function (err) {
                  done(err, user);
                });
              });
            });
          } else {
            req.flash("error", "Passwords do not match.");
            return res.redirect(`/reset/${req.params.token}/sms`);
          }
        }
      );
    },
    function (user) {
      var client = new twilio(accountSid, authToken);

      client.messages
        .create({
          body:
            "Your password has been changed" +
            "Hello,\n\n" +
            "This is a confirmation that the password for your account " +
            user.email +
            " has just been changed.\n",
          to: `+91${user.phno}`, // Text this number
          from: twilioPhno, // From a valid Twilio number
        })
        .then(() => {
          req.flash(
            "success",
            " SMS has been sent to " + user.phno + " with further instructions."
          );
          res.redirect("/");
        })
        .catch((err) => {
          req.flash("error", err.message);
          res.redirect("/forgotPassword");
        });
    },

    function (err) {
      res.redirect("/");
    },
  ]);
};

module.exports.logout = (req, res) => {
  req.logout();
  req.flash("success", "Goodbye");
  res.redirect("/");
};
