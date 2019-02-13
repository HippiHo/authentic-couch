require("dotenv").config({ path: "./.env" });
const bcrypt = require("bcrypt");

const express = require("express");
const bodyParser = require("body-parser");
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const morgan = require("morgan");
const mongoose = require("mongoose");
const cors = require("cors");

app.use(cors());
app.use(morgan("dev"));

const jwt = require("jsonwebtoken");
const Location = require("./Location");
const User = require("./User");

const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);

const uuidv4 = require("uuid/v4");
const sendVerificationEmail = require("./helper/mailer");

const mongopath = process.env.MONGOPATH || `localhost`;
const port = process.env.PORT || 8080;

mongoose.connect(`mongodb://${mongopath}:27017/DCI6jsonwebtoken`, {
  useNewUrlParser: true
});
app.set("superSecret", "thisshouldbesupersecret");

(async () => {
  const locations = await Location.find({});
  if (locations.length == 0) {
    console.log(`No locations in database, lets create some`);
    const titles = [
      "Oranienburg",
      "Potsdam",
      "Eisenhuettenstadt",
      "Stuttgart",
      "Rostock",
      "Hamburg"
    ];
    for (let i = 0; i < titles.length; i++) {
      Location.create({
        name: titles[i]
      });
    }
  }
  const users = await User.find({});
  if (users.length == 0) {
    console.log(`No user in database, lets create some`);
    const user = new User({
      name: "alice",
      password: "password",
      admin: true
    });
    await user.save();
    console.log("User saved successfully");
  }
})();

app.get("/", function(req, res) {
  res.send("Hello! The API is at http://localhost:" + port + "/api");
});
app.post("/", function(req, res) {
  console.log("req.body", req.body);

  res.send("Hello! The API is at http://localhost:" + port + "/api");
});

const apiRoutes = express.Router();

apiRoutes.post("/authenticate", function(req, res) {
  User.findOne(
    {
      name: req.body.name
    },
    function(err, user) {
      if (err) throw err;

      if (!user) {
        res.json({
          success: false,
          message: "Authentication failed. User not found."
        });
      } else if (user) {
        // TODO 4 we need bcrypt to hash our passwords and compare with hash in db
        const hashedPW = bcrypt.compareSync(req.body.password, user.password); // true

        if (!hashedPW) {
          return res.json({
            success: false,
            message: "Authentication failed. Wrong password."
          });
        } else if (user.verified === false) {
          return res.json({
            success: false,
            message: "E-Mail verification pending. Check your Inbox!"
          });
        } else {
          const payload = {
            user: user.name,
            admin: user.admin
          };
          const token = jwt.sign(payload, app.get("superSecret"), {
            expiresIn: 86400
          });

          return res.json({
            success: true,
            user: user,
            message: "Enjoy your token!",
            token: token
          });
        }
      }
    }
  );
});
// TODO 2 Here should come a singup route which creates a new user if the username is not already taken
// example:
// apiRoutes.post("/signup", async (req, res) => {
// });

// TODO 4 we need bcrypt to hash our passwords while signup
// TODO 4 The flow is like this:
// 1. signup, hash password, save hash in db
// 2. signin, hash password, compare with hash in DB
// 3. send token to client

// TODO 5 generate a unique ID with uuid 4, save it to the db while signup
// TODO 5 send mail with nodemailer with  token-verification link
// TODO 5 dont save the user directly in the signup route, add a token to the User model and verify it with a http://localhost:${port}/api/verify/${verificationToken} link

// TODO 6 validate the user after clicking in the mails link
// example
// apiRoutes.get("/verify/:verification_hash", async (req, res) => {
//   const user = await User.findOne({
//     verificationToken: req.params.verification_hash
//   });

//   ...

//   res.redirect("http://localhost:3000?verified=true");
// });

apiRoutes.post("/signup", async (req, res) => {
  const user = await User.findOne({ name: req.body.name });

  if (user) {
    return res.json({
      success: false,
      status: 409,
      message: "Username already exists."
    });
  } else {
    const hash = bcrypt.hashSync(req.body.password, salt);
    const user = new User({
      name: req.body.name,
      password: hash,
      verificationToken: uuidv4()
    });

    await user.save();

    let verificationToken = user.verificationToken;

    sendVerificationEmail(req, res, verificationToken);

    return res.json({
      success: true,
      status: 201,
      message: `User created`
    });
  }
});

apiRoutes.get("/verify/:verification_hash", async (req, res) => {
  const user = await User.findOne(
    {
      verificationToken: req.params.verification_hash
    },
    function(err, user) {
      (user.verified = true), user.save();

      res.redirect("http://localhost:3000?verified=true");
    }
  );
});

apiRoutes.use(function(req, res, next) {
  const token = req.headers["x-access-token"];

  if (token) {
    try {
      const decoded = jwt.verify(token, app.get("superSecret"));

      req.decoded = decoded;
      //This actually makes this function to a middleware and forwards to the authenticated routes
      next();
    } catch (e) {
      return res.json({
        success: false,
        message: "Failed to authenticate token."
      });
    }
  } else {
    return res.status(403).send({
      success: false,
      message: "No token provided."
    });
  }
});

apiRoutes.get("/", function(req, res) {
  console.log("req.decoded", req.decoded);

  res.json({
    message: `Welcome ${req.decoded.user} to the coolest API on earth!`
  });
});

apiRoutes.get("/locations", function(req, res) {
  Location.find({}, function(err, locations) {
    res.json(locations);
  });
});

apiRoutes.get("/check", function(req, res) {
  res.json(req.decoded);
});

app.use("/api", apiRoutes);

app.listen(port);
console.log(``);
console.log(`#######################################################`);
console.log("The api-url is localhost:" + port);
console.log(``);
console.log(
  `A user is in the database with name: alice and password: password`
);
console.log(``);
console.log(
  `The plan is to authenticate that user with postman per /api/authenticate and the name and password per raw/json`
);
console.log(`#######################################################`);
console.log(``);
