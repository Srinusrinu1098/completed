const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const app = express();
app.use(express.json());

// Connect to database
const db = new sqlite3.Database("./twitterClone.db");

// JWT secret key
const JWT_SECRET = "your_secret_key";

// Middleware for JWT token authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send("Invalid JWT Token");
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).send("Invalid JWT Token");
    }
    req.user = user;
    next();
  });
};

// API 1: Register
app.post("/register/", async (req, res) => {
  const { username, password, name, gender } = req.body;

  db.get(
    `SELECT * FROM user WHERE username = ?`,
    [username],
    async (err, user) => {
      if (user) {
        return res.status(400).send("User already exists");
      }
      if (password.length < 6) {
        return res.status(400).send("Password is too short");
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(
        `INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)`,
        [name, username, hashedPassword, gender],
        (err) => {
          if (err) {
            return res.status(500).send("Error registering user");
          }
          res.status(200).send("User created successfully");
        }
      );
    }
  );
});

// API 2: Login
app.post("/login/", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM user WHERE username = ?`,
    [username],
    async (err, user) => {
      if (!user) {
        return res.status(400).send("Invalid user");
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).send("Invalid password");
      }

      const jwtToken = jwt.sign({ userId: user.user_id }, JWT_SECRET);
      res.status(200).send({ jwtToken });
    }
  );
});

// API 3: Get Latest Tweets of Following Users
// API 3: Get Latest Tweets of Following Users
app.get("/user/tweets/feed/", authenticateToken, (req, res) => {
  const { userId } = req.user;
  db.all(
    `SELECT u.username, t.tweet, t.date_time 
        FROM tweet t
        JOIN follower f ON f.following_user_id = t.user_id
        JOIN user u ON u.user_id = t.user_id
        WHERE f.follower_user_id = ?
        ORDER BY t.date_time DESC LIMIT 4`,
    [userId],
    (err, rows) => {
      if (err) {
        return res.status(500).send("Error fetching tweets");
      }
      const tweets = rows.map((row) => ({
        username: row.username,
        tweet: row.tweet,
        dateTime: row.date_time,
      }));
      res.send(tweets);
    }
  );
});

// API 4: Get Following Users
app.get("/user/following/", authenticateToken, (req, res) => {
  const { userId } = req.user;

  db.all(
    `SELECT u.name 
        FROM follower f
        JOIN user u ON u.user_id = f.following_user_id
        WHERE f.follower_user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        return res.status(500).send("Error fetching following users");
      }
      res.send(rows);
    }
  );
});

// API 5: Get Followers
app.get("/user/followers/", authenticateToken, (req, res) => {
  const { userId } = req.user;

  db.all(
    `SELECT u.name 
        FROM follower f
        JOIN user u ON u.user_id = f.follower_user_id
        WHERE f.following_user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        return res.status(500).send("Error fetching followers");
      }
      res.send(rows);
    }
  );
});

// API 6: Get Tweet Details by ID
// API 6: Get Tweet Details by ID
app.get("/tweets/:tweetId/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.get(
    `SELECT t.tweet, 
                (SELECT COUNT(*) FROM like WHERE tweet_id = t.tweet_id) AS likes, 
                (SELECT COUNT(*) FROM reply WHERE tweet_id = t.tweet_id) AS replies,
                t.date_time 
        FROM tweet t 
        JOIN follower f ON f.following_user_id = t.user_id 
        WHERE t.tweet_id = ? AND f.follower_user_id = ?`,
    [tweetId, userId],
    (err, tweet) => {
      if (!tweet) {
        return res.status(401).send("Invalid Request");
      }
      res.send({
        tweet: tweet.tweet,
        likes: tweet.likes,
        replies: tweet.replies,
        dateTime: tweet.date_time,
      });
    }
  );
});

// API 7: Get Likes for a Tweet
app.get("/tweets/:tweetId/likes/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.all(
    `SELECT u.username 
        FROM like l 
        JOIN user u ON u.user_id = l.user_id 
        JOIN tweet t ON t.tweet_id = l.tweet_id 
        JOIN follower f ON f.following_user_id = t.user_id 
        WHERE l.tweet_id = ? AND f.follower_user_id = ?`,
    [tweetId, userId],
    (err, likes) => {
      if (err || likes.length === 0) {
        return res.status(401).send("Invalid Request");
      }
      res.send({ likes: likes.map((like) => like.username) });
    }
  );
});

// API 8: Get Replies for a Tweet
app.get("/tweets/:tweetId/replies/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.all(
    `SELECT u.name, r.reply 
        FROM reply r 
        JOIN user u ON u.user_id = r.user_id 
        JOIN tweet t ON t.tweet_id = r.tweet_id 
        JOIN follower f ON f.following_user_id = t.user_id 
        WHERE r.tweet_id = ? AND f.follower_user_id = ?`,
    [tweetId, userId],
    (err, replies) => {
      if (err || replies.length === 0) {
        return res.status(401).send("Invalid Request");
      }
      res.send({ replies });
    }
  );
});

// API 9: Get All Tweets of the Logged-in User
// API 9: Get All Tweets of the Logged-in User
app.get("/user/tweets/", authenticateToken, (req, res) => {
  const { userId } = req.user;

  db.all(
    `SELECT t.tweet, 
                (SELECT COUNT(*) FROM like WHERE tweet_id = t.tweet_id) AS likes, 
                (SELECT COUNT(*) FROM reply WHERE tweet_id = t.tweet_id) AS replies,
                t.date_time 
        FROM tweet t 
        WHERE t.user_id = ?`,
    [userId],
    (err, tweets) => {
      if (err) {
        return res.status(500).send("Error fetching tweets");
      }
      const result = tweets.map((tweet) => ({
        tweet: tweet.tweet,
        likes: tweet.likes,
        replies: tweet.replies,
        dateTime: tweet.date_time,
      }));
      res.send(result);
    }
  );
});

// API 10: Create a Tweet
app.post("/user/tweets/", authenticateToken, (req, res) => {
  const { tweet } = req.body;
  const { userId } = req.user;

  db.run(
    `INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, ?)`,
    [tweet, userId, new Date().toISOString()],
    (err) => {
      if (err) {
        return res.status(500).send("Error creating tweet");
      }
      res.send("Created a Tweet");
    }
  );
});

// API 11: Delete a Tweet
app.delete("/tweets/:tweetId/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.run(
    `DELETE FROM tweet WHERE tweet_id = ? AND user_id = ?`,
    [tweetId, userId],
    function (err) {
      if (this.changes === 0) {
        return res.status(401).send("Invalid Request");
      }
      res.send("Tweet Removed");
    }
  );
});

module.exports = app; // Export the express app
