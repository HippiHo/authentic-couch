# Authentic-Couch | user-facing web-frontend for JWT-API backend

Install and run the client `cd frontend && npm install && npm start`  
Install and run the API `cd backend && npm install && npm start`  
Api on localhost:8080

Seeded in database:

```
Location = [
    "Oranienburg",
    "Potsdam",
    "Eisenhuettenstadt",
    "Stuttgart",
    "Rostock",
    "Hamburg"
];

User = {
    name: "alice",
    password: "password",
    admin: true
};
```

## Todos


### frontend/src/Login.jsx

1. [TODO 1 This component should be Register and Signin at the same time](./frontend/src/Login.jsx#L4)
1. [TODO 1 transform this into a functional component](./frontend/src/Login.jsx#L6)
1. [TODO 1 update react + react-dom to 16.8](./frontend/src/Login.jsx#L7)
1. [TODO 1 add the conditionals isSignin state value to render the form differently](./frontend/src/Login.jsx#L8)
1. [TODO 3 the form also needs now to pass this information to the submit function in the parent](./frontend/src/Login.jsx#L16)

### frontend/src/App.js

1. [TODO 3 this function must now handle two submit-types, signup and signin](./frontend/src/App.js#L52)

### api/index.js

1. [TODO 2 Here should come a singup route which creates a new user if the username is not already taken](./api/index.js#L109)
1. [TODO 4 we need bcrypt to hash our passwords while signup](./api/index.js#L114)
1. [TODO 4 we need bcrypt to hash our passwords and compare with hash in db](./api/index.js#L83)
1. [TODO 4 The flow is like this:](./api/index.js#L115)
1. [TODO 5 generate a unique ID with uuid 4, save it to the db while signup](./api/index.js#L120)
1. [TODO 5 send mail with nodemailer with token-verification link](./api/index.js#L121)
1. [TODO 5 dont save the user directly in the signup route, add a token to the User model and verify it with a http://localhost:${port}/api/verify/${verificationToken} link](./api/index.js#L122)
1. [TODO 6 validate the user after clicking in the mails link](./api/index.js#L124)

## api/User.js
  
1. [TODO 6 the user needs two values for getting verified. A token holder and a verified flag ](./api/User.js#L10)