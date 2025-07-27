# Implementing-security-measures-in-web-application


I implemented 4 security measures in the web application NodeGoat, you can access the application and its all data from here https://github.com/kikiyani/Security-Assessment-of-a-web-application.git


### security measures implemented:

Sanitize and Validate Inputs:
Use the validator library to validate user inputs:
npm install validator

Sanitize inputs in your route handlers: const
validator = require(validator);
if (!validator.isEmail(email)) {
return res.status(400).send(Invalid email);
}

Password Hashing: Use bcrypt to hash
passwords: npm install bcrypt const
bcrypt = require(bcrypt);
const hashedPassword = await bcrypt.hash(password, 10);

2. Enhance Authentication
Add basic token-based authentication using jsonwebtoken:
npm install jsonwebtoken const jwt =
require(jsonwebtoken);
const token = jwt.sign({ id: user._id }, your-secret-key);
res.send({ token });

3. Secure Data Transmission
Use Helmet.js to secure HTTP headers:
npm install helmet const helmet
= require(helmet);
app.use(helmet());
