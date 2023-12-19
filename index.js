const express = require("express");
const app = express();
const db = require("./models");
const { Users } = require("./models");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { createTokens, validateToken } = require("./JWT");

app.use(express.json());
app.use(cookieParser());

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  // Pastikan username, email, dan password tersedia
  if (!username || !email || !password) {
    return res.status(400).json({ error: "Username, email, and password are required" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await Users.create({
      username: username,
      email: email,
      password: hash,
    });
    res.json("USER REGISTERED");
  } catch (err) {
    res.status(400).json({ error: err.message || "Failed to register user" });
  }
});


app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await Users.findOne({ where: { email: email } });
    if (!user) {
      return res.status(400).json({ error: "User Doesn't Exist" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "Wrong Email and Password Combination!" });
    }

    const accessToken = createTokens(user);

    res.cookie("access-token", accessToken, {
      maxAge: 60 * 60 * 24 * 30 * 1000,
      httpOnly: true,
    });

    res.json("LOGGED IN");
  } catch (err) {
    res.status(400).json({ error: err.message || "Failed to login" });
  }
});

app.get("/profile", validateToken, (req, res) => {
  try {
    // Dapatkan informasi pengguna dari token yang valid
    const user = req.authData;

    // Di sini, Anda dapat menyesuaikan dengan cara mendapatkan informasi profil yang sesuai
    // Misalnya, Anda dapat melakukan query ke database atau menggunakan informasi yang sudah ada
    // Di contoh ini, kita hanya mengembalikan beberapa informasi pengguna
    const userProfile = {
      id: user.id,
      username: user.username,
      email: user.email,
      // tambahkan properti lain sesuai kebutuhan
    };

    res.status(200).json({ message: "Profile retrieved successfully", userProfile });
  } catch (err) {
    res.status(400).json({ error: err.message || "Failed to retrieve profile" });
  }
});

db.sequelize.sync().then(() => {
  app.listen(3001, () => {
    console.log("Server running on port 3001");
  });
});
