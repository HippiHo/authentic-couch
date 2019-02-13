import React, { Component } from "react";
import Login from "./Login.jsx";
import Nav from "./Nav.jsx";
import "./App.css";
import Locations from "./Locations.jsx";
import { BrowserRouter as Router, Route, Redirect } from "react-router-dom";

const domain = process.env.REACT_APP_DOMAIN || "http://localhost";
const port = process.env.REACT_APP_BACKENDPORT || 8080;
class App extends Component {
  state = {
    user: false,
    alert: false,
    loading: false,
    form: {
      name: "",
      password: ""
    }
  };
  componentWillMount = () => {
    const user = localStorage.getItem("user");
    if (user) {
      this.setState({
        user: {
          name: JSON.parse(localStorage.getItem("user")).name,
          token: JSON.parse(localStorage.getItem("user")).token
        }
      });
    }
  };
  onChange = event => {
    let form = { ...this.state.form };
    form[event.target.id] = event.target.value;
    this.setState({ form });
  };
  showNotification = alert => {
    this.setState({ alert: alert });
    setTimeout(
      function() {
        this.setState({ alert: false });
      }.bind(this),
      3000
    );
  };
  logout = () => {
    this.showNotification({ success: "Logged out!" });

    localStorage.removeItem("user");
    this.setState({ user: null, loading: false });
  };
  onSubmit = (event, isSignin) => {
    // TODO 3 this function must now handle two submit-types, signup and signin
    // example:
    // onSubmit = (event, isSignin) => {
    //   const path = isSignin ? `authenticate` : `signup`;
    //   ...
    event.preventDefault();
    this.setState({
      loading: true
    });
    const path = isSignin ? `authenticate` : `signup`;

    const body = JSON.stringify({
      name: this.state.form.name.toLowerCase(),
      password: this.state.form.password
    });

    fetch(`${domain}:${port}/api/${path}`, {
      method: "POST",
      body: body,
      headers: {
        "Content-Type": "application/json"
      }
    })
      .then(res => res.json())
      .then(data => {
        if (data.token) {
          this.showNotification({ success: data.message });

          if (isSignin) {
            localStorage.setItem(
              "user",
              JSON.stringify({ name: data.user.name, token: data.token })
            );
            this.setState({
              user: {
                name: data.user.name,
                token: data.user.token,
                loading: false
              }
            });
          }
        } else if (data.status === 201) {
          this.setState({ loading: false });
          this.showNotification({ success: data.message });
        } else if (!data.success) {
          this.setState({ user: false, loading: false });
          this.showNotification({ error: data.message });
        }
      })
      .catch(err => {
        console.log(err);
        this.setState({ loading: false });
      });
  };
  render() {
    let alert = "";
    if (this.state.alert.error) {
      alert = (
        <div className="alert alert-danger fixed-bottom text-center mb-0">
          {this.state.alert.error}{" "}
        </div>
      );
    } else if (this.state.alert.success) {
      alert = (
        <div className="alert alert-success fixed-bottom text-center mb-0">
          {this.state.alert.success}{" "}
        </div>
      );
    }
    return (
      <Router>
        <div className="h-100">
          {alert}

          <Nav user={this.state.user} logout={this.logout} />

          <Route
            exact
            path="/"
            render={() =>
              this.state.user ? (
                <Redirect to={{ pathname: "/locations" }} />
              ) : (
                <Login
                  loading={this.state.loading}
                  onChange={this.onChange}
                  onSubmit={this.onSubmit}
                />
              )
            }
          />
          <Route
            exact
            path="/locations"
            render={() =>
              this.state.user ? (
                <div>
                  <Locations user={this.state.user} />
                </div>
              ) : (
                <Redirect to={{ pathname: "/" }} />
              )
            }
          />
        </div>
      </Router>
    );
  }
}
export default App;
