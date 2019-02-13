import React, { useState } from "react";
import logo from "./logo.svg";

// TODO 1 This component should be Register and Signin at the same time

//TODO 1 transform this into a functional component
//TODO 1 update react + react-dom to 16.8
//TODO 1 add the conditionals isSignin state value to render the form differently

// example code:
// const [isSignin, setSignin] = useState(true);
// <span className="text-muted" onClick={() => setSignin(!isSignin)}>
// {isSignin ? "Signin" : "Register"}
// onSubmit={event => props.onSubmit(event, isSignin)}

//TODO 3 the form also needs now to pass this information to the submit function in the parent
const Login = props => {
  const [isSignin, setSignin] = useState(true);
  return (
    <div className="h-100">
      <div className="App">
        <form
          onSubmit={event => props.onSubmit(event, isSignin)}
          className="form-signin"
        >
          <img src={logo} className="App-logo" alt="logo" />
          <h1 className="h3 my-5 font-weight-normal">
            {isSignin ? "Signin" : "Register"}
          </h1>
          <label htmlFor="name" className="sr-only">
            Name
          </label>
          <input
            onChange={props.onChange}
            type="text"
            id="name"
            className="form-control"
            placeholder="Name"
            required
            autoFocus
          />
          <label htmlFor="password" className="sr-only">
            Password
          </label>
          <input
            onChange={props.onChange}
            type="password"
            id="password"
            className="form-control"
            placeholder="Password"
            required
          />
          <div className="checkbox mb-3">
            <label>
              <input type="checkbox" value="remember-me" /> Remember me
            </label>
          </div>
          <button
            disabled={props.loading}
            className={`${
              isSignin ? "btn-outline-primary" : "btn-primary"
            } mb-3 btn btn-lg  btn-block`}
          >
            {!props.loading ? (isSignin ? "Signin" : "Register") : "Loading"}
          </button>
          <br />
          <button
            className="btn btn-outline-primary"
            onClick={() => setSignin(!isSignin)}
          >
            {isSignin
              ? "If you don't have an account please switch here to register."
              : "If you have an account please switch here to signin."}
          </button>
          <p className="mt-5 mb-3 text-muted">&copy; 2017-2018</p>
        </form>
      </div>
    </div>
  );
};

export default Login;
