import express from "express";
import pg from "pg";
import env from "dotenv";
import path from "path";
import cors from "cors";
import bodyParser from "body-parser";
import multer from "multer";
import fs from "fs";
import util from "util";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const port = 9000;
const saltRounds = 10;
app.use(cors());

env.config();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public"));
const secretKey = process.env.SESSION_SECRET;

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

const unlinkAsync = util.promisify(fs.unlink);

const profstorage = multer.diskStorage({
  destination: function (req, file, cb) {
    return cb(null, "./public/profimg");
  },
  filename: function (req, file, cb) {
    return cb(
      null,
      file.fieldname + "_" + Date.now() + path.extname(file.originalname)
    );
  },
});

async function deleteFile(filePath) {
  try {
    await unlinkAsync(filePath);
    console.log(`Successfully deleted ${filePath}`);
  } catch (error) {
    console.error(`Error deleting ${filePath}:`, error);
  }
}

const generateToken = (user) => {
  return jwt.sign({ id: user.id }, secretKey, { expiresIn: "30d" });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, secretKey);
  } catch (err) {
    return null;
  }
};

const authenticateToken = (req, res, next) => {
  const token = req.body.token;
  if (!token) return res.sendStatus(401);

  const verifiedUser = verifyToken(token);
  if (!verifiedUser) return res.sendStatus(403);

  req.user = verifiedUser;
  next();
};

app.get("/data", async (req, res) => {
  try {
    const dataretrive = await db.query("SELECT * FROM products LIMIT 8");
    return res.json(dataretrive.rows).end();
  } catch (err) {
    console.error(err);
    return res.json({ error: "Internal Server Error" });
  }
});

app.get("/home/bestseller", async (req, res) => {
  try {
    const bestseller = await db.query("SELECT * FROM bestseller");
    return res.json(bestseller.rows).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.get("/browseproducts/women", async (req, res) => {
  try {
    const products = await db.query(
      "SELECT * FROM products WHERE gender = 'women' ORDER BY RANDOM() LIMIT 36"
    );
    return res.json(products.rows).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.get("/browseproducts/newarrivals", async (req, res) => {
  try {
    const products = await db.query("SELECT * FROM products LIMIT 36");
    return res.json(products.rows).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.get("/browseproducts/men", async (req, res) => {
  try {
    const products = await db.query(
      "SELECT * FROM products WHERE gender = 'men' and category !='accessories' ORDER BY RANDOM() LIMIT 36"
    );
    return res.json(products.rows).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.get("/browseproducts/access", async (req, res) => {
  try {
    const products = await db.query(
      "SELECT * FROM products WHERE category = 'accessories' ORDER BY RANDOM() LIMIT 36"
    );
    return res.json(products.rows).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.get("/profile/:uid", async (req, res) => {
  const uid = req.params.uid;
  try {
    const udata = await db.query("SELECT * FROM users WHERE id = $1", [uid]);
    // console.log(udata);
    return res.json(udata.rows[0]).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.post("/cartdata", authenticateToken, async (req, res) => {
  const cart = req.body.uid;
  try {
    const cartdataa = await db.query(
      "SELECT * FROM cart INNER JOIN products on cart.product_id = products.id WHERE user_id = $1 and status = 0",
      [cart]
    );

    return res.json(cartdataa.rows).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.get("/orders/:uidcheck", async (req, res) => {
  const cart = req.params.uidcheck;
  try {
    const ordersData = await db.query(
      "SELECT * FROM cart INNER JOIN products on cart.product_id = products.id WHERE user_id = $1 and status = 1",
      [cart]
    );
    return res.json(ordersData.rows).end();
  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.delete("/deleteItem", async (req, res) => {
  const productId = req.body.id; // Assuming 'id' is the product ID from the request body
console.log(productId);
  try { 
    await db.query(
      "DELETE FROM cart WHERE id = $1", // Correct DELETE statement
      [productId]
    );
    return res.json("Success").end(); // Sends back the deleted rows (if needed)
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.patch("/buyitem", authenticateToken, async (req, res) => {
  const { pid, uid } = req.body;
  console.log(pid, uid);
  // Ensure pid is an array and not empty
  if (!Array.isArray(pid) || pid.length === 0) {
    return res.status(400).json({ error: "Invalid product IDs" });
  }
  try {
    const result = await db.query(`UPDATE cart SET status = 1 WHERE user_id = $1 AND product_id = ANY($2::int[])`,
      [uid, pid]
    );

    if(result.rowCount>0){
      return res.json({status: "buyed"})
    }
    else{
      return res.status(404).json({error: "Cart is empty"})
    }

  } catch (error) {
    console.error(error);
    return res.json({ error: "Internal Server Error" });
  }
});

app.post("/signup/user", async (req, res) => {
  const phonenumber = req.body.phonenumber;
  const email = req.body.email;
  const password = req.body.password;

  const hashPassword = await bcrypt.hash(password, saltRounds);

  try {
    const isUser = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (isUser.rowCount > 0) {
      console.log("User already exists");
      return res.json({ error: "User already exists" });
    } else {
      const result = await db.query(
        "INSERT INTO users (pnum, email, passhash) VALUES ($1, $2, $3) RETURNING *",
        [phonenumber, email, hashPassword]
      );
      console.log(result);
      const user = result.rows[0];
      res.status(201).json(user);
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/addtocart", authenticateToken, async (req, res) => {
  const uid = req.body.uid;
  const pid = req.body.pid;
  const count = req.body.count;
  try {
    await db.query(
      "INSERT INTO cart (user_id, product_id, quantity) VALUES ($1, $2, $3)",
      [uid, pid, count]
    );
    return res.status(201).json({ status: "Added" });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.passhash))) {
      const token = generateToken(user);
      res.json({ token, uid: user.id });
    } else {
      res.json({ error: "Invalid credentials" });
    }
  } catch (error) {
    res.status(500).json({ error: error.meggase });
  }
});

app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Thie is a protected route", user: req.user });
});

app.listen(port, () => {
  console.log(`Server running on port http://localhost:${port}`);
});
