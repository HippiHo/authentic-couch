import React, { Component } from "react";

function Nav(props) {
  let status = (
    <span className="nav-link disabled" href="#">
      Logged out
    </span>
  );
  let logout = "";

  if (props.user) {
    status = (
      <span className="nav-link text-muted" href="#">
        Logged in as {props.user.name}
      </span>
    );
    logout = (
      <button
        className="ml-3 btn btn-outline-danger nav-item"
        href="#"
        onClick={props.logout}
      >
        Logout
      </button>
    );
  } 
  return (
    <nav className="navbar navbar-expand fixed-top navbar-light bg-light">
      <a className="navbar-brand" href="#">
        Authentic-Couch
      </a>
      <button
        className="navbar-toggler"
        type="button"
        data-toggle="collapse"
        data-target="#navbarNav"
        aria-controls="navbarNav"
        aria-expanded="false"
        aria-label="Toggle navigation"
      >
        <span className="navbar-toggler-icon" />
      </button>
      <div
        className="collapse justify-content-end navbar-collapse"
        id="navbarNav"
      >
        <ul className="navbar-nav">
          <li className="nav-item">{status}</li>
          <li className="nav-item">{logout}</li>
        </ul>
      </div>
    </nav>
  );
}
export default Nav;
