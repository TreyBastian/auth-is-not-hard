const express = require("express");
const app = express();
const port = 3000;
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

const db = {
  users: [
    {
      username: "test",
      hashed_password:
        "$2b$10$LdYyMU57TiyMIcsRqyyKvu.y7GIzmNyLM3iiJTcpFpQjtGMl/SSG.",
      roles: ["ADMIN", "USER"],
    },
  ],
  session: [],
};

// our login -> oauthservice -> /login/callback (recieve credentials)

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const authn = (req, res, next) => {
  // grab the cookie or header
  const cookie = req.cookies?.authIsEasy;

  const sessionIdx = db.session.findIndex((c) => c.id === cookie);
  const sessionValid =
    sessionIdx > -1 && db.session[sessionIdx]?.expiresAt > Date.now();

  // check if valid session
  if (sessionValid) {
    res.cookie("authIsEasy", cookie, { maxAge: 90000, httpOnly: true });
    db.session[sessionIdx].expiresAt = Date.now() + 90000;
    req.session = db.session[sessionIdx];
    next();
  } else {
    db.session.splice(sessionIdx, 1);
    res.send(401);
  }
};

const authz =
  (...role) =>
  (req, res, next) => {
    if (req.session?.user?.roles?.includes(role)) {
      next();
      return;
    }
    res.send(403);
  };
const middlewares = [authn, authz("ADMIN")];

const userMiddlewares = [authn, authz("USER")];
app.get("/", (req, res) => {
  res.send("unauthenticated");
});

app.get("/user", userMiddlewares, (req, res) => {
  res.send("Im a user");
});

app.get("/admin", middlewares, (req, res) => {
  res.send(
    '<a href="/admin/page">some other page</a> super secret stuff here <form action="/logout" method="post"><button type="submit">Logout</button>',
  );
});

app.get("/admin/page", middlewares, (req, res) => {
  res.send('<a href="/admin">Go Back</a>');
});

app.get("/registration", (req, res) => {
  res.send(`<html><head></head><body><form action="/registration" method="post"><input type="text" name="username" placeholder="username" /><input type="password" name="password" placeholder="password" />
    <button type="submit">Submit</button>
    </form><body></html>`);
});

app.post("/logout", (req, res) => {
  const cookie = req.cookies?.authIsEasy;
  if (cookie) {
    const idx = db.session.findIndex((s) => s.id === cookie);
    console.log(idx);
    db.session.splice(idx, 1);
  }

  res.redirect("/");
});

app.post("/registration", (req, res) => {
  const hashed_password = bcrypt.hashSync(req.body.password, 10);

  // database library would be using prepared statements to prevent SQL injection attacks in a real application
  db.users.push({
    username: req.body.username,
    hashed_password: hashed_password,
  });
  // do not do this log this is for reference purposes only
  console.log(db);

  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.send(`<html><head></head><body><h1>Login</h1><form action="/login" method="post"><input type="text" name="username" placeholder="username" /><input type="password" name="password" placeholder="password" />
    <button type="submit">Submit</button>
    </form><body></html>`);
});

app.post("/login", (req, res) => {
  const user = db.users.find((u) => (u.username = req.body.username));
  if (!user) {
    res.redirect("/login");
    return;
  }
  const isPasswordValid = bcrypt.compareSync(
    req.body.password,
    user.hashed_password,
  );

  if (!isPasswordValid) {
    res.redirect("/login");
    return;
  }
  const sessionId = crypto.randomUUID();
  db.session.push({ id: sessionId, user: user, expiresAt: Date.now() + 90000 });

  res.cookie("authIsEasy", sessionId, { maxAge: 90000, httpOnly: true });

  res.redirect("/admin");
});

app.listen(port, () => {
  console.log(`App is running on port ${port}`);
});
