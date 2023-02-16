import dotenv from "dotenv";
dotenv.config();
import bodyParser from "body-parser";
import express, { response } from "express";
import Jwt from "jsonwebtoken";
import axios from "axios";

const app = express();
app.use(express.json());
app.use(bodyParser.json());

const usersData = [];

//-----------------------------------------REGISTER------------------------------------------------------------
app.post("/register", (req, res) => {
  // Do the necessary stuffs to check whether we have everything required or not in the request
  const requiredFields = [
    "username",
    "password",
    "name",
    "college",
    "yearofgraduation",
  ];

  for (let i = 0; i < requiredFields.length; i++) {
    if (!(requiredFields[i] in req.body)) {
      return res.status(400).send({
        message: `Missing ${requiredFields[i]} field in request body`,
      });
    }
  }

  // Do the necessary checks (like whether username already taken by anyone else)
  const existingUser = usersData.find(
    (user) => user.username === req.body.username
  );

  try {
    if (existingUser) {
      return res.status(400).json({ error: "Username already taken" });
    }
  } catch (err) {
    return console.log(err);
  }

  const currentUserData = {
    username: req.body.username, // fill this value by taking from the request
    password: req.body.password,
    name: req.body.name,
    college: req.body.college,
    yearofgraduation: req.body.yearofgraduation,
  };

  // push the data to the global array, so that it is visible (and can be used) by other APIs as well
  usersData.push(currentUserData);
  //--for email sending api----------
  const emailContent = {
    to: req.body.username,
    subject: "Registration Successful",
    body: `You have successfully registered at ${new Date()}.`,
  };
  
  res.set( "x-private-api-key",process.env.SHARED_SECRET);
  const headers = {"x-private-api-key" : process.env.SHARED_SECRET}
  
  // call the send-email API
  // synchronously
  // axios.post("/send-email", emailContent, { headers });
  
  // asynchronously
  axios
    .post("http://localhost:7050/send-email", emailContent, { headers })
    .then((response) => {
      console.log(response);
      console.log(`Email sent for Registration`);
    })
    .catch((error) => {
      console.log(error);
    });
  res.status(200).json({ message: "Successfully registered!" });
});

//------------------------------------ GETTING ALL DATA FROM USERS-------------------------------------------------
app.get("/profile", (req, res) => {
  //creating a reference what will i need only from the users
  const users = usersData.map((user) => {
    const { username, college, name, yearofgraduation } = user;
    return { username, college, name, yearofgraduation };
  });
  res.status(201).json(users);
});

// ------------------------------------MIDDLEWARE------------------------------------------------------------------
const authenticationLogic = (req, res, next) => {
  const token = req.headers["auth-token"];
  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }
  try {
    const decodedInfo = Jwt.verify(token, process.env.PRIVATE_KEY);
    req.userInfo = decodedInfo;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

//------------------------------------------- UPDATING INFO OF LEGITIMATE USER-------------------------------------------
app.put("/profile", authenticationLogic, (req, res) => {
  // extract the 'username' from decrypted json token information from the 'userInfo' field of the 'req'
  const username = req.userInfo.username;
  // update the user information corresponding to 'username' fetched in the previous step
  const user = usersData.find((user) => user.username === username);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  Object.assign(user, req.body);
  res.status(200).json({ message: "Profile updated successfully" });
});

// -------------------------------------------------------LOGIN-------------------------------------------------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = usersData.find(
    (user) =>
      user.username === req.body.username && user.password === req.body.password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid username and password" });
  } else {
    // create a JWT with a 1 hour expiration time
    const token = Jwt.sign({ username }, process.env.PRIVATE_KEY, {
      expiresIn: "1h",
    });
    // send the JWT in the response header
    res.set("auth-token", token);    

     //--for email sending api----------
     const emailContent = {
        to: user.username,
        subject: "Login Successful",
        body: `You have successfully logged in to your account at ${new Date()}.`,
      };
      
      res.set( "x-private-api-key",process.env.SHARED_SECRET);
      const headers = {"x-private-api-key" : process.env.SHARED_SECRET}
      
      // call the send-email API
      // synchronously
      // axios.post("/send-email", emailContent, { headers });
      
      // asynchronously
      axios
        .post("http://localhost:7050/send-email", emailContent, { headers })
        .then((response) => {
          console.log(response);
          console.log(`Email sent for Logging in`);
        })
        .catch((error) => {
          console.log(error);
        });

    return res.status(200).json({ message: "Login Successful" });
  }
});

// ----------------------------------------SENDING EMAIL---------------------------------------
app.post("/send-email", (req, res) => {
    const privateApiKey = req.headers["x-private-api-key"];
    
    if (!privateApiKey) {
    return res.status(400).json({ message: "Missing x-private-api-key header" });
    }
    
    if (privateApiKey !== process.env.SHARED_SECRET) {
    return res.status(401).json({ message: "Invalid x-private-api-key" });
    }
    
    const emailContent = req.body;
    
    console.log("Email content: ", emailContent);
    
    res.status(200).json({ message: "Email sent successfully" });
    });


// ------------------------------------PORT CONFIGURATION-------------------------------------------
const port = process.env.PORT;
app.listen(port, () => {
  console.log(`Listening to the port ${port}`);
});
