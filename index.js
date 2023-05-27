const express = require("express");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const User = require("./models/user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ejs = require("ejs");
dotenv.config();

const app = express();

const isAuthenticated = (req, res, next) => {
	try {
		const user = jwt.verify(req.headers.token, process.env.JWT_SECRET_KEY)
		req.user = user
	} catch (error) {
		return res.send({ status: "FAIL", message: "Please login first" });
	}
	next()
};

const isAuthorized = (req, res, next) => {
	console.log(req.user)
	if(Boolean(req.user.isAdmin)) {
		return next()
	}
	return res.send({ status: "FAIL", message: "Access denied" });	
};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static("./public"));

app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.send({ message: "All good!" });
});

app.post("/register", async (req, res) => {
  const { email, password, isAdmin } = req.body;
	try {
		const user = await User.findOne({ email });
		if(user) {
			return res.send({
        status: "FAIL",
        message: "User already exists with the provided email",
      });
		}

		const encryptedPassword = await bcrypt.hash(password, 10)

		await User.create({
			email,
			password: encryptedPassword,
			isAdmin,
		})
		const jwtToken = jwt.sign(
			{ email, isAdmin },
			process.env.JWT_SECRET_KEY,
			{ expiresIn: 60 }
		);
		res.send({ status: "SUCCESS", message: "User created successfully", jwtToken })
	} catch (error) {
		res.send({ error })
	}
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
		if(user) {
			let passwordMatch = await bcrypt.compare(password, user.password)
			if(passwordMatch) {
				const { isAdmin } = user;
				const jwtToken = jwt.sign(
          { email, isAdmin },
          process.env.JWT_SECRET_KEY,
          { expiresIn: 60 }
        );
				return res.send({
					status: "SUCCESS",
					message: "User logged in successfully",
					jwtToken
				});
			}
		}
    res.send({ status: "FAIL", message: "Incorrect credentials" });
  } catch (error) {
    res.send({ error });
  }
});

app.get("/private-route", isAuthenticated, (req, res) => {
  res.send({ message: "Welcome user!" });
});

app.get("/admin-route", isAuthenticated, isAuthorized, (req, res) => {
  res.send({ message: "Welcome Admin!" });
});

app.listen(process.env.PORT, () => {
  mongoose
    .connect(process.env.MONGO_DB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => console.log(`Server running on port: ${process.env.PORT}`))
    .catch((error) => console.log(error));
});
















/*
	## Authentication and Authorization
	- Authentication: Verify user's identity (Who are you?)
	- Authorization: Check access of authenticated user (What access does the user have?)
	- JSON Web Token (JWT)

	- Securing user's password
	- bcrypt
*/
