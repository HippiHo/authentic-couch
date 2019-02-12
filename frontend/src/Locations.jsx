import React, { Component } from "react";
import PropTypes from "prop-types";
import logo from "./logo.svg";
const domain = process.env.REACT_APP_DOMAIN || "http://localhost";
const port = process.env.REACT_APP_BACKENDPORT || 8080;
class Locations extends Component {
  state = {
    locations: []
  };
  componentWillMount = () => {
    const token = localStorage.getItem("user");
    try {
      this.getLocations(JSON.parse(token).token);
    } catch (e) {
      console.error("failed", e);
    }
  };
  getLocations = async token => {
    fetch(`${domain}:${port}/api/locations`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "x-access-token": `${token}`
      }
    })
      .then(res => res.json())
      .then(data => {
        this.setState({ locations: data });
      })
      .catch(err => {
        console.log("fetch in Locations.jsx failed: ", err);
      });
  };

  render() {
    const posttemplate = (
      <table className="py-5 table">
        <thead>
          <tr>
            <th scope="col">#</th>
            <th scope="col">Title</th>
            <th scope="col">Date</th>
          </tr>
        </thead>
        <tbody>
          {this.state.locations &&
            this.state.locations.map(scan => (
              <tr key={scan._id}>
                <th>{scan._id}</th>
                <td>{scan.name}</td>
                <td>{scan.createdAt}</td>
              </tr>
            ))}
        </tbody>
      </table>
    );
    return (
      <div className="container py-5">
        <div className="text-center">
          <img src={logo} className="my-5 App-logo" alt="logo" />
        </div>
        <h2>
          Hey{" "}
          {this.props.user.name.charAt(0).toUpperCase() +
            this.props.user.name.slice(1)}
          , this are your Locations:
        </h2>
        {posttemplate}
      </div>
    );
  }
}

Locations.propTypes = {
  user: PropTypes.object
};

export default Locations;
