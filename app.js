import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
const __dirname = path.resolve();

mongoose.connect("mongodb://localhost:27017/backend", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Database connected');
}).catch((err) => {
  console.error('Database connection error:', err);
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const Userschema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const TodoSchema = new mongoose.Schema({
  task: String,
});

const User = mongoose.model("User", Userschema);
const Todo = mongoose.model("Todo", TodoSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

const secretKey = 'yourSecretKey';

const isAuthenticated = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.render('login');
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.render('login');
    }
    req.user = decoded;
    next();
  });
};

app.get('/', isAuthenticated, async (req, res) => {
  try {
    const tasks = await Todo.find();
    res.render('index', { tasks });
  } catch (error) {
    console.error("Error retrieving tasks:", error);
    res.status(500).send("Error retrieving tasks: " + error.message);
  }
});

app.get('/register', async (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  const user = await User.findOne({ email: email });
  if (user) {
    return res.redirect('/login');
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
    });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, secretKey, { expiresIn: '1h' });
    res.cookie("token", token, {
      httpOnly: true,
      expires: new Date(Date.now() + 3600000),
    });
    res.redirect("/");
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).send("Error creating user: " + error.message);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.render('login', { message: "Incorrect email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.render('login', { message: "Incorrect email or password" });
    }

    const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });

    res.cookie("token", token, {
      httpOnly: true,
      expires: new Date(Date.now() + 3600000)
    });
    
    res.redirect("/");
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).send("Error during login: " + error.message);
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/add', isAuthenticated, async (req, res) => {
  const { task } = req.body;

  try {
    await Todo.create({ task });
    res.redirect('/');
  } catch (error) {
    console.error("Error adding task:", error);
    res.status(500).send("Error adding task");
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
