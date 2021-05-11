const Localstrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

//load User Model
const User = require("../models/User");

module.exports = function (passport) {
  passport.use(
    new Localstrategy({ usernameField: "email" }, (email, password, done) => {
      //match User
      User.findOne({ email: email })
        .then((user) => {
          if (!user) {
            return done(null, false, {
              message: "That email is not registered",
            });
          }

          //Match password
          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;
            if (isMatch) {
              return done(null, user);
            } else {
              return done(null, false, { message: "Password incorrect" });
            }
          });
        })
        .catch((err) => console.log(err));
    })
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  }); //en la serializacion el dato(un objeto) se convierte en bytes o xml o json

  passport.deserializeUser((id, done) => {
    User.findById(id, function (err, user) {
      done(err, user);
    });
  }); //en la deserializacion consiste en la reconstrucción del objeto a partir de la información recuperada
};
