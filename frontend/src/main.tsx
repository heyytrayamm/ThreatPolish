import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
import { applyTheme, readTheme } from "./theme";

// Before the first paint, so a daylight session never flashes the dark field.
applyTheme(readTheme());

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
